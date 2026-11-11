"""Tests for gptk_phone_check.py. Run: python3 -m unittest discover -s tools/phone-check -v"""

import base64
import contextlib
import datetime as dt
import errno
import hashlib
import io
import json
import os
import random
import stat
import tempfile
import time
import unicodedata
import unittest
from unittest import mock

import gptk_phone_check as phone

WHATSAPP_MEDIA = "Android/media/com.whatsapp/WhatsApp/Media"
SCAN_ID = "0123456789abcdef0123456789abcdef"


def fingerprint_of(data: bytes) -> str:
    """Fingerprint computed independently of the script: base64 of the SHA-1 digest."""
    return base64.b64encode(hashlib.sha1(data).digest()).decode("ascii")


def gptk_time(moment: dt.datetime) -> str:
    """Time text in the form that GPTK writes (JavaScript toISOString)."""
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class FakePhone:
    """A temporary folder laid out like the phone storage (/storage/emulated/0)."""

    def __init__(self, root: str):
        self.root = root
        self.downloads = os.path.join(root, "Download")
        os.makedirs(self.downloads)

    def path(self, relative_path: str) -> str:
        return os.path.join(self.root, relative_path)

    def add(self, relative_path: str, data: bytes) -> str:
        path = self.path(relative_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def add_whatsapp(self, relative_path: str, data: bytes) -> str:
        return self.add(f"{WHATSAPP_MEDIA}/{relative_path}", data)

    def run(self, *args, answers=("yes",), ask=None):
        """Runs the script. Each question gets the next answer. After the last answer, the input is closed (like Ctrl+D)."""
        asked = []
        remaining = list(answers)

        def default_ask(prompt):
            asked.append(prompt)
            if not remaining:
                raise EOFError()
            return remaining.pop(0)

        with contextlib.redirect_stdout(io.StringIO()):
            code = phone.main([*args, "--storage", self.root], ask=ask or default_ask)
        return code, asked

    def fingerprint_file(self) -> str:
        return os.path.join(self.downloads, "gptk-fingerprints.json")

    def fingerprints(self) -> list:
        with open(self.fingerprint_file(), encoding="utf-8") as handle:
            return json.load(handle)["hashes"]

    def write_fingerprint_file(self, scan_id: str = SCAN_ID) -> str:
        """A fingerprint file like the one that scan writes, so that a result can belong to it."""
        content = {"format": "gptk-phone-check", "type": "fingerprints", "version": 1, "created": "2026-01-01T00:00:00Z", "scanId": scan_id, "hashes": []}
        return self.write_text("gptk-fingerprints.json", json.dumps(content))

    def scan_id(self) -> str:
        with open(self.fingerprint_file(), encoding="utf-8") as handle:
            return json.load(handle)["scanId"]

    def write_result(self, google_items: dict, name: str = "gptk-result.json", **overrides) -> str:
        """A GPTK result for the last scan (a fingerprint file is made first if there is none)."""
        if not os.path.exists(self.fingerprint_file()):
            self.write_fingerprint_file()
        content = {
            "format": "gptk-phone-check",
            "type": "result",
            "version": 1,
            "created": gptk_time(dt.datetime.now(dt.timezone.utc)),
            "scanId": self.scan_id(),
            "complete": True,
            "counts": {
                "checked": len(google_items),
                "found": len(google_items),
                "notFound": 0,
                "inTrash": 0,
                "notInLibrary": 0,
                "notOriginalQuality": 0,
                "notChecked": 0,
            },
            "found": [{"hash": hash_value, "mediaKey": key} for hash_value, key in google_items.items()],
        }
        content.update(overrides)
        return self.write_text(name, json.dumps(content))

    def write_text(self, name: str, text: str) -> str:
        path = os.path.join(self.downloads, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def holding(self) -> str:
        """The folder where "yes" moves the files to."""
        return os.path.join(self.downloads, "GPTK-deleted")

    def batches(self) -> list:
        """The folders in GPTK-deleted, one for each "yes", oldest first."""
        if not os.path.isdir(self.holding()):
            return []
        return sorted(name for name in os.listdir(self.holding()) if os.path.isdir(os.path.join(self.holding(), name)))

    def moved_list(self) -> list:
        """The entries of the lists of moved files in GPTK-deleted, oldest first."""
        entries = []
        for batch in self.batches():
            list_path = os.path.join(self.holding(), batch, "moved-files.json")
            if os.path.exists(list_path):
                with open(list_path, encoding="utf-8") as handle:
                    entries += [dict(entry, batch=batch) for entry in json.load(handle)["files"]]
        return entries

    def held_files(self) -> list:
        """(folder, name, content) of each file that GPTK-deleted holds, without the lists of moved files."""
        found = []
        for batch in self.batches():
            for name in sorted(os.listdir(os.path.join(self.holding(), batch))):
                if name != "moved-files.json":
                    with open(os.path.join(self.holding(), batch, name), "rb") as handle:
                        found.append((batch, name, handle.read()))
        return found

    def held_contents(self) -> list:
        return sorted(content for _, _, content in self.held_files())

    def snapshot(self) -> dict:
        """Path -> (content, modified time) of each file on the phone, without GPTK-deleted and the GPTK files in Download."""
        files = {}
        for current, dirs, names in os.walk(self.root):
            if current == self.downloads:
                dirs[:] = [name for name in dirs if name != "GPTK-deleted"]
            for name in names:
                path = os.path.join(current, name)
                if current == self.downloads and name.startswith("gptk-"):
                    continue
                if os.path.islink(path):
                    files[path] = ("link", os.readlink(path))
                else:
                    with open(path, "rb") as handle:
                        files[path] = (handle.read(), os.lstat(path).st_mtime_ns)
        return files


class PhoneTestCase(unittest.TestCase):
    def setUp(self):
        self.phone = self.fresh_phone()

    def fresh_phone(self) -> FakePhone:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return FakePhone(temp.name)


class ScanTests(PhoneTestCase):
    # The fingerprint file holds the SHA-1 fingerprint of every photo and video in the WhatsApp folder.
    def test_scan_fingerprints_every_photo_and_video(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-20240101-WA0001.jpg", b"photo")
        self.phone.add_whatsapp("WhatsApp Video/VID-20240101-WA0002.mp4", b"video")

        code, _ = self.phone.run("scan")

        self.assertEqual(code, 0, msg="scan succeeds")
        self.assertEqual(sorted(self.phone.fingerprints()), sorted([fingerprint_of(b"photo"), fingerprint_of(b"video")]), msg="each file has its SHA-1 fingerprint")

    # The fingerprint file is marked so that GPTK accepts it.
    def test_scan_writes_a_file_that_gptk_recognises(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")

        self.phone.run("scan")

        with open(self.phone.fingerprint_file(), encoding="utf-8") as handle:
            content = json.load(handle)
        self.assertEqual((content["format"], content["type"], content["version"]), ("gptk-phone-check", "fingerprints", 1), msg="GPTK knows this file type")

    # Hidden folders and files, stickers, other file types and links are left out.
    def test_scan_skips_what_it_must_not_touch(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"normal photo")
        self.phone.add_whatsapp("WhatsApp Images/.trashed-1-IMG-2.jpg", b"hidden file")
        self.phone.add_whatsapp(".Statuses/status.jpg", b"status")
        self.phone.add_whatsapp("WhatsApp Stickers/sticker.webp", b"sticker")
        self.phone.add_whatsapp("WhatsApp Voice Notes/PTT-1.opus", b"voice note")
        self.phone.add_whatsapp("WhatsApp Documents/notes.txt", b"text")
        outside = self.phone.add("DCIM/Camera/outside.jpg", b"outside photo")
        os.symlink(outside, self.phone.path(f"{WHATSAPP_MEDIA}/WhatsApp Images/link.jpg"))
        os.symlink(os.path.dirname(outside), self.phone.path(f"{WHATSAPP_MEDIA}/WhatsApp Images/linked-folder"))

        self.phone.run("scan")

        self.assertEqual(self.phone.fingerprints(), [fingerprint_of(b"normal photo")], msg="only the normal photo is fingerprinted")

    # The same photo in two places gives one fingerprint.
    def test_scan_lists_each_fingerprint_once(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"same photo")
        self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"same photo")

        self.phone.run("scan")

        self.assertEqual(self.phone.fingerprints(), [fingerprint_of(b"same photo")], msg="copies share one fingerprint")

    # The fingerprint file must not show which files are on the phone.
    def test_scan_writes_no_file_names(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-20240101-WA0001.jpg", b"photo")

        self.phone.run("scan")

        with open(self.phone.fingerprint_file(), encoding="utf-8") as handle:
            text = handle.read()
        self.assertNotIn("IMG-20240101-WA0001", text, msg="file names stay on the phone")
        self.assertNotIn("WhatsApp", text, msg="folder names stay on the phone")

    # Scanning never changes or deletes a file.
    def test_scan_changes_no_files(self):
        paths = [self.phone.add_whatsapp(f"WhatsApp Images/IMG-{index}.jpg", f"photo {index}".encode()) for index in range(3)]

        self.phone.run("scan")

        for index, path in enumerate(paths):
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), f"photo {index}".encode(), msg="every file is still there, unchanged")

    # Without a WhatsApp folder, scan stops and writes no file.
    def test_scan_without_folders_fails(self):
        code, _ = self.phone.run("scan")

        self.assertEqual(code, 2, msg="scan reports that it found no folder")
        self.assertFalse(os.path.exists(self.phone.fingerprint_file()), msg="no fingerprint file is written")

    # With --folder, only that folder is scanned. The folder can be relative to the phone storage or a full path.
    def test_scan_uses_only_the_chosen_folder(self):
        for chosen in ("relative path", "full path"):
            with self.subTest(chosen=chosen):
                phone = self.fresh_phone()
                phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"whatsapp photo")
                phone.add("DCIM/Test/photo.jpg", b"test photo")

                phone.run("scan", "--folder", phone.path("DCIM/Test") if chosen == "full path" else "DCIM/Test")

                self.assertEqual(phone.fingerprints(), [fingerprint_of(b"test photo")], msg="only the chosen folder is read")

    # Without --folder, every folder with "WhatsApp" in its name is scanned, wherever it is in the phone storage, and no other folder.
    def test_scan_reads_every_whatsapp_folder(self):
        inside = {
            f"{WHATSAPP_MEDIA}/WhatsApp Images/IMG-1.jpg": b"folder that WhatsApp uses",
            "Android/media/com.whatsapp.w4b/WhatsApp Business/Media/WhatsApp Video/VID-1.mp4": b"WhatsApp Business",
            "WhatsApp/Media/WhatsApp Images/IMG-2.jpg": b"old WhatsApp folder",
            "storage-0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/VID-2.mp4": b"copy from an old phone",
            "Pictures/whatsapp saved/photo.jpg": b"own folder",
        }
        for relative, data in inside.items():
            self.phone.add(relative, data)
        self.phone.add("DCIM/Camera/IMG_3.jpg", b"camera photo")
        self.phone.add("Android/media/org.telegram.messenger/Telegram/IMG-4.jpg", b"other app")

        code, _ = self.phone.run("scan")

        self.assertEqual(code, 0, msg="scan succeeds")
        self.assertEqual(
            sorted(self.phone.fingerprints()),
            sorted(fingerprint_of(data) for data in inside.values()),
            msg="the files in all WhatsApp folders are read, and no other files",
        )

    # The search for WhatsApp folders skips hidden, trash, sticker, GPTK-deleted and private app folders, and does not follow links.
    def test_scan_skips_whatsapp_folders_it_must_not_touch(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"normal photo")
        for place in (
            "DCIM/.hidden/WhatsApp/IMG-2.jpg",
            "Pictures/Trash/WhatsApp/IMG-3.jpg",
            "WhatsApp Stickers/sticker.webp",
            "Download/GPTK-deleted/WhatsApp/IMG-4.jpg",
            "Android/data/com.whatsapp/files/IMG-5.jpg",
            "Android/obb/com.whatsapp/IMG-6.jpg",
        ):
            self.phone.add(place, place.encode())
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        with open(os.path.join(outside.name, "IMG-7.jpg"), "wb") as handle:
            handle.write(b"outside the phone storage")
        os.symlink(outside.name, self.phone.path("WhatsApp link"))

        self.phone.run("scan")

        self.assertEqual(self.phone.fingerprints(), [fingerprint_of(b"normal photo")], msg="only the photo in the WhatsApp folder is read")

    # A chosen folder that does not exist is an error, not a silent switch to other folders.
    def test_scan_with_a_missing_chosen_folder_fails(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"whatsapp photo")

        code, _ = self.phone.run("scan", "--folder", "DCIM/Missing")

        self.assertEqual(code, 2, msg="scan reports the missing folder")
        self.assertFalse(os.path.exists(self.phone.fingerprint_file()), msg="no fingerprint file is written")


class CleanTests(PhoneTestCase):
    # With the suggestion and "yes", every WhatsApp copy of a file that is in Google Photos is deleted, and nothing else.
    def test_clean_deletes_only_files_in_google_photos(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        backed_up_copy = self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"in google photos")
        phone_only = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"only on the phone")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        code, asked = self.phone.run("clean", answers=["", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 2, msg="the user is asked about the copies, then once before deleting")
        self.assertFalse(os.path.exists(backed_up), msg="the backed-up file is deleted")
        self.assertFalse(os.path.exists(backed_up_copy), msg="its copy is deleted too")
        self.assertTrue(os.path.exists(phone_only), msg="a file that is not in Google Photos is kept")

    # Clean deletes the files that are in Google Photos from every WhatsApp folder, and leaves the other folders alone.
    def test_clean_uses_every_whatsapp_folder(self):
        contents = (b"photo 1", b"video 2", b"photo 3", b"photo 4")
        whatsapp = [
            self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", contents[0]),
            self.phone.add("storage-0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/VID-2.mp4", contents[1]),
            self.phone.add("WhatsApp/Media/WhatsApp Images/IMG-3.jpg", contents[2]),
        ]
        camera = self.phone.add("DCIM/Camera/IMG_4.jpg", contents[3])
        self.phone.write_result({fingerprint_of(data): f"AF1QipItem{index}" for index, data in enumerate(contents)})

        code, _ = self.phone.run("clean", answers=["yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertFalse(any(os.path.exists(path) for path in whatsapp), msg="the files in all WhatsApp folders are deleted")
        self.assertTrue(os.path.exists(camera), msg="the camera photo stays, because only WhatsApp folders are cleaned")

    # Any answer other than "yes" deletes nothing.
    def test_clean_keeps_everything_without_yes(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        for answer in ["", "y", "no", "yes please"]:
            with self.subTest(answer=answer):
                code, _ = self.phone.run("clean", answers=[answer])

                self.assertEqual(code, 1, msg="clean reports that it was cancelled")
                self.assertTrue(os.path.exists(backed_up), msg="nothing is deleted without a clear yes")

    # Closing the input (Ctrl+D or Ctrl+C) deletes nothing.
    def test_clean_keeps_everything_when_the_question_is_closed(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        for error in (EOFError, KeyboardInterrupt):
            with self.subTest(error=error.__name__):

                def ask(_prompt, error=error):
                    raise error()

                code, _ = self.phone.run("clean", ask=ask)

                self.assertEqual(code, 1, msg="clean reports that it was cancelled")
                self.assertTrue(os.path.exists(backed_up), msg="nothing is deleted when the question is closed")

    # A file that changes while the question is open is kept.
    def test_clean_keeps_a_file_that_changed_after_the_check(self):
        changed = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first photo")
        unchanged = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second photo")
        self.phone.write_result({fingerprint_of(b"first photo"): "AF1QipFirst", fingerprint_of(b"second photo"): "AF1QipSecond"})

        def ask(_prompt):
            with open(changed, "wb") as handle:
                handle.write(b"edited photo")
            return "yes"

        self.phone.run("clean", ask=ask)

        self.assertTrue(os.path.exists(changed), msg="a file that no longer matches Google Photos is kept")
        self.assertFalse(os.path.exists(unchanged), msg="the unchanged file is still deleted")

    # A damaged, foreign or old result file deletes nothing, and no question is asked.
    def test_clean_refuses_bad_result_files(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        good_hash = fingerprint_of(b"in google photos")
        old_time = gptk_time(dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3))
        bad_files = {
            "text that is not JSON": "hello",
            "a file of another tool": json.dumps({"found": [{"hash": good_hash, "mediaKey": "AF1Qip"}]}),
            "a fingerprint file": json.dumps({"format": "gptk-phone-check", "type": "fingerprints", "version": 1, "hashes": [good_hash]}),
        }
        bad_results = {
            "another file type": {"type": "fingerprints"},
            "another version": {"version": 2},
            "a version that is not a number": {"version": True},
            "no list of found files": {"found": None},
            "a damaged fingerprint": {"found": [{"hash": hashlib.sha1(b"in google photos").hexdigest(), "mediaKey": "AF1Qip"}]},
            "a damaged item key": {"found": [{"hash": good_hash, "mediaKey": "../../evil key"}]},
            "no creation time": {"created": None},
            "a result older than 2 days": {"created": old_time},
            "no scan ID": {"scanId": None},
            "a damaged scan ID": {"scanId": "../" + SCAN_ID[3:]},
        }
        cases = [(label, lambda text=text: self.phone.write_text("gptk-result.json", text)) for label, text in bad_files.items()]
        cases += [(label, lambda change=change: self.phone.write_result({good_hash: "AF1Qip"}, **change)) for label, change in bad_results.items()]

        for label, write in cases:
            with self.subTest(file=label):
                write()

                code, asked = self.phone.run("clean")

                self.assertEqual(code, 2, msg="clean refuses the result file")
                self.assertEqual(asked, [], msg="the user is not even asked")
                self.assertTrue(os.path.exists(backed_up), msg="nothing is deleted")

    # When there is no result file, clean stops.
    def test_clean_without_a_result_file_fails(self):
        photo = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")

        code, asked = self.phone.run("clean")

        self.assertEqual(code, 2, msg="clean reports the missing result file")
        self.assertEqual(asked, [], msg="the user is not asked")
        self.assertTrue(os.path.exists(photo), msg="nothing is deleted")

    # After a new scan, a result of the earlier scan is refused, because it may be outdated.
    def test_clean_refuses_a_result_of_an_earlier_scan(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.run("scan")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("scan")

        code, asked = self.phone.run("clean")

        self.assertEqual(code, 2, msg="clean refuses the result of the earlier scan")
        self.assertEqual(asked, [], msg="the user is not even asked")
        self.assertTrue(os.path.exists(backed_up), msg="nothing is deleted")

    # Without the fingerprint file, clean cannot tell which scan is the last one, so it deletes nothing.
    def test_clean_refuses_a_result_without_the_fingerprint_file(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        os.remove(self.phone.fingerprint_file())

        code, asked = self.phone.run("clean")

        self.assertEqual(code, 2, msg="clean refuses to work without the fingerprint file")
        self.assertEqual(asked, [], msg="the user is not even asked")
        self.assertTrue(os.path.exists(backed_up), msg="nothing is deleted")

    # With several downloaded results, the newest one is used.
    def test_clean_uses_the_newest_result(self):
        older_match = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"older match")
        newer_match = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"newer match")
        older = self.phone.write_result({fingerprint_of(b"older match"): "AF1QipOlder"}, name="gptk-result.json")
        past = time.time() - 600
        os.utime(older, (past, past))
        self.phone.write_result({fingerprint_of(b"newer match"): "AF1QipNewer"}, name="gptk-result(1).json")

        self.phone.run("clean")

        self.assertTrue(os.path.exists(older_match), msg="the older result is not used")
        self.assertFalse(os.path.exists(newer_match), msg="the newest result is used")

    # A link inside the folder never leads to deleting a file outside it.
    def test_clean_never_follows_links(self):
        outside = self.phone.add("DCIM/Camera/photo.jpg", b"in google photos")
        link = self.phone.path(f"{WHATSAPP_MEDIA}/WhatsApp Images/link.jpg")
        os.makedirs(os.path.dirname(link))
        os.symlink(outside, link)
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        self.phone.run("clean")

        self.assertTrue(os.path.exists(outside), msg="the file outside the WhatsApp folder is kept")
        self.assertTrue(os.path.lexists(link), msg="the link itself is not touched")

    # A file that is replaced by a link while the question is open stays where it is.
    def test_a_file_that_became_a_link_is_not_moved(self):
        for case in ("link to the copy that stays", "link to a file in Google Photos"):
            with self.subTest(case=case):
                device = self.fresh_phone()
                whatsapp = device.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
                if case == "link to the copy that stays":
                    target = device.add("DCIM/Camera/IMG_1.jpg", b"photo")
                    device.write_result({})
                else:
                    target = device.add(".private/IMG_1.jpg", b"photo")
                    device.write_result({fingerprint_of(b"photo"): "AF1QipPhoto"})
                answers = ["", "yes"] if case == "link to the copy that stays" else ["yes"]

                def ask(_prompt, whatsapp=whatsapp, target=target, answers=answers):
                    answer = answers.pop(0)
                    if answer == "yes":
                        os.remove(whatsapp)
                        os.symlink(target, whatsapp)
                    return answer

                device.run("clean", ask=ask)

                self.assertTrue(os.path.islink(whatsapp), msg="the link stays in the WhatsApp folder")
                self.assertTrue(os.path.exists(target), msg="the file that the link leads to stays on the phone")
                self.assertEqual(device.held_files(), [], msg="no file is moved")

    # The list of moved files shows where each file was and where it is in Google Photos.
    def test_moved_list_shows_each_file_and_its_google_photos_link(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"only on the phone")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        self.phone.run("clean")

        self.assertEqual(
            [(entry["from"], entry["size"], entry["googlePhotos"], entry["keptCopy"]) for entry in self.phone.moved_list()],
            [(backed_up, len(b"in google photos"), "https://photos.google.com/photo/AF1QipBackedUp", None)],
            msg="the list shows the moved file, its size, where it is in Google Photos and that no copy stays on the phone",
        )

    # When the phone refuses to move a file, the other files are still moved and clean reports the problem.
    def test_clean_reports_files_it_could_not_move(self):
        locked = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first photo")
        free = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second photo")
        self.phone.write_result({fingerprint_of(b"first photo"): "AF1QipFirst", fingerprint_of(b"second photo"): "AF1QipSecond"})
        real_rename = os.rename

        def rename(source, target):
            if source == locked:
                raise PermissionError("not allowed")
            real_rename(source, target)

        with mock.patch.object(phone.os, "rename", side_effect=rename):
            code, _ = self.phone.run("clean")

        self.assertEqual(code, 3, msg="clean reports that some files could not be moved")
        self.assertTrue(os.path.exists(locked), msg="the refused file is still there")
        self.assertFalse(os.path.exists(free), msg="the other file is moved")
        self.assertEqual(self.phone.held_contents(), [b"second photo"], msg="GPTK-deleted holds only the moved file")
        self.assertEqual([entry["from"] for entry in self.phone.moved_list()], [free], msg="the list names only files that really moved")

    # When no phone file matches, nothing is asked and nothing is deleted.
    def test_clean_with_no_matching_files_asks_nothing(self):
        photo = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"only on the phone")

        for found in ({fingerprint_of(b"a different photo"): "AF1QipOther"}, {}):
            with self.subTest(found=len(found)):
                self.phone.write_result(found)

                code, asked = self.phone.run("clean")

                self.assertEqual(code, 0, msg="there is simply nothing to do")
                self.assertEqual(asked, [], msg="the user is not asked")
                self.assertTrue(os.path.exists(photo), msg="nothing is deleted")


class CopyTests(PhoneTestCase):
    """Files that have more than one copy on the phone."""

    # By default, the copy outside WhatsApp stays and the WhatsApp copy is deleted, in Google Photos or not.
    def test_suggestion_keeps_the_copy_outside_whatsapp(self):
        for in_google in (True, False):
            with self.subTest(in_google=in_google):
                phone = self.fresh_phone()
                whatsapp = phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
                camera = phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
                phone.write_result({fingerprint_of(b"photo"): "AF1QipPhoto"} if in_google else {})

                code, _ = phone.run("clean", answers=["", "yes"])

                self.assertEqual(code, 0, msg="clean succeeds")
                self.assertFalse(os.path.exists(whatsapp), msg="the WhatsApp copy is deleted")
                self.assertTrue(os.path.exists(camera), msg="the camera copy stays on the phone")

    # In the old WhatsApp folder (not in an app folder), the copy outside WhatsApp stays, also when the WhatsApp copy is older.
    def test_suggestion_keeps_the_copy_outside_the_old_whatsapp_folder(self):
        whatsapp = self.phone.add("WhatsApp/Media/WhatsApp Images/IMG-1.jpg", b"photo")
        os.utime(whatsapp, (time.time() - 86400 * 365, time.time() - 86400 * 365))
        pictures = self.phone.add("Pictures/IMG_1.jpg", b"photo")

        code, _ = self.phone.run("copies", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertFalse(os.path.exists(whatsapp), msg="the older WhatsApp copy is deleted")
        self.assertTrue(os.path.exists(pictures), msg="the copy outside WhatsApp stays on the phone")

    # When all copies are in WhatsApp folders, the suggestion keeps the copy in the folder that WhatsApp uses, so that the chat still shows it.
    def test_suggestion_keeps_the_copy_that_whatsapp_uses(self):
        cases = (
            (f"{WHATSAPP_MEDIA}/WhatsApp Video/VID-1.mp4", "storage-0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/VID-1.mp4"),
            (f"{WHATSAPP_MEDIA}/WhatsApp Video/VID-1.mp4", "WhatsApp/Media/WhatsApp Video/VID-1.mp4"),
            (f"{WHATSAPP_MEDIA}/WhatsApp Video/VID-1.mp4", "Pictures/WhatsApp/VID-1.mp4"),
            ("Android/media/com.whatsapp.w4b/WhatsApp Business/Media/WhatsApp Video/VID-1.mp4", "WhatsApp Business/Media/WhatsApp Video/VID-1.mp4"),
        )
        for used_place, other_place in cases:
            with self.subTest(other=other_place):
                phone = self.fresh_phone()
                used = phone.add(used_place, b"video")
                other = phone.add(other_place, b"video")
                past = time.time() - 86400 * 365
                os.utime(other, (past, past))

                code, _ = phone.run("copies", answers=["", "yes"])

                self.assertEqual(code, 0, msg="copies succeeds")
                self.assertTrue(os.path.exists(used), msg="the copy that WhatsApp uses stays, also when the other copy is older")
                self.assertFalse(os.path.exists(other), msg="the copy in the other WhatsApp folder is moved")

    # A WhatsApp folder inside the folder of another app (Android/media/...) is not the folder that WhatsApp uses.
    # That app can delete its files at any time, so the suggestion keeps the copy outside app folders.
    def test_suggestion_does_not_prefer_another_apps_whatsapp_folder(self):
        other_app = self.phone.add("Android/media/com.example.statussaver/WhatsApp/VID-1.mp4", b"video")
        old_folder = self.phone.add("WhatsApp/Media/WhatsApp Video/VID-1.mp4", b"video")
        past = time.time() - 86400 * 365
        os.utime(other_app, (past, past))

        code, _ = self.phone.run("copies", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertTrue(os.path.exists(old_folder), msg="the copy outside app folders stays, also when the other copy is older")
        self.assertFalse(os.path.exists(other_app), msg="the copy in the folder of the other app is moved")

    # A chosen folder given through a link to the phone storage (like /sdcard/...) is the same folder as in the storage.
    def test_chosen_folder_through_a_link_to_the_storage(self):
        used = self.phone.add("Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/VID-1.mp4", b"video")
        other = self.phone.add("storage-0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video/VID-1.mp4", b"video")
        past = time.time() - 86400 * 365
        os.utime(other, (past, past))
        links = tempfile.TemporaryDirectory()
        self.addCleanup(links.cleanup)
        sdcard = os.path.join(links.name, "sdcard")
        os.symlink(self.phone.root, sdcard)

        code, _ = self.phone.run(
            "copies", "--folder", os.path.join(sdcard, "Android/media/com.whatsapp"), "--folder", "storage-0", answers=["", "yes"]
        )

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertTrue(os.path.exists(used), msg="the copy that WhatsApp uses stays, also when it was chosen through a link")
        self.assertFalse(os.path.exists(other), msg="the copy in the other WhatsApp folder is moved")

    # The suggestion keeps a copy in a gallery folder rather than one in Download, which is often emptied.
    def test_suggestion_prefers_a_gallery_folder_to_download(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
        download = self.phone.add("Download/VID-1.mp4", b"video")
        gallery = self.phone.add("Pictures/Saved/funny video.mp4", b"video")

        code, _ = self.phone.run("copies", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertTrue(os.path.exists(gallery), msg="the copy in the gallery folder stays")
        self.assertFalse(os.path.exists(download) or os.path.exists(whatsapp), msg="the other copies are deleted")

    # Among copies in equally good places, the suggestion keeps the oldest one, which is usually the original.
    def test_suggestion_keeps_the_oldest_copy(self):
        for older in ("DCIM/Camera/IMG_1.jpg", "Pictures/Saved/photo copy.jpg"):
            with self.subTest(older=older):
                device = self.fresh_phone()
                whatsapp = device.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
                others = [device.add("DCIM/Camera/IMG_1.jpg", b"photo"), device.add("Pictures/Saved/photo copy.jpg", b"photo")]
                past = time.time() - 86400 * 365
                os.utime(device.path(older), (past, past))

                code, _ = device.run("copies", answers=["", "yes"])

                left = [path for path in [whatsapp, *others] if os.path.exists(path)]
                self.assertEqual(code, 0, msg="copies succeeds")
                self.assertEqual(left, [device.path(older)], msg="only the oldest copy stays on the phone")

    # A copy number keeps only that copy, and each number keeps a different copy.
    def test_a_number_keeps_only_that_copy(self):
        kept = set()
        for number in ("1", "2", "3"):
            with self.subTest(number=number):
                phone = self.fresh_phone()
                copies = [
                    phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"),
                    phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"photo"),
                    phone.add("Pictures/IMG-1.jpg", b"photo"),
                ]
                phone.write_result({})

                code, _ = phone.run("clean", answers=[number, "yes"])

                left = [os.path.relpath(path, phone.root) for path in copies if os.path.exists(path)]
                self.assertEqual(code, 0, msg="clean succeeds")
                self.assertEqual(len(left), 1, msg="exactly one copy stays")
                kept.update(left)
        self.assertEqual(len(kept), 3, msg="each number keeps a different copy")

    # "skip" keeps every copy, and then there is nothing left to ask.
    def test_skip_keeps_every_copy(self):
        copies = [self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"), self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")]
        self.phone.write_result({fingerprint_of(b"photo"): "AF1QipPhoto"})

        code, asked = self.phone.run("clean", answers=["skip"])

        self.assertEqual(code, 0, msg="keeping everything is a normal end")
        self.assertEqual(len(asked), 1, msg="there is no last question when nothing is to be deleted")
        self.assertTrue(all(os.path.exists(path) for path in copies), msg="every copy is kept")

    # "all" deletes every copy of a file that is in Google Photos, also outside WhatsApp, with no extra question.
    def test_all_deletes_every_copy_of_a_file_in_google_photos(self):
        copies = [self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"), self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")]
        self.phone.write_result({fingerprint_of(b"photo"): "AF1QipPhoto"})

        code, asked = self.phone.run("clean", answers=["all", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 2, msg="no extra question, because Google Photos has the file")
        self.assertFalse(any(os.path.exists(path) for path in copies), msg="every copy is deleted")

    # Deleting every copy of a file that Google Photos may not have needs the extra word "delete".
    def test_all_copies_of_a_file_not_in_google_photos_need_the_word_delete(self):
        cases = [
            ("delete", ["all", "delete", "yes"], False),
            ("Enter", ["all", "", "skip"], True),
            ("yes", ["all", "yes", "skip"], True),
        ]
        for command in ("clean", "copies"):
            for confirmation, answers, kept in cases:
                with self.subTest(command=command, confirmation=confirmation):
                    phone = self.fresh_phone()
                    copies = [phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"), phone.add("Download/IMG-1.jpg", b"photo")]
                    phone.write_result({})

                    phone.run(command, answers=answers)

                    self.assertEqual([os.path.exists(path) for path in copies], [kept, kept], msg="only the word delete allows deleting every copy")

    # Without Google Photos, the suggestion always keeps one copy, also when all copies are in WhatsApp.
    def test_suggestion_keeps_one_copy_of_a_file_not_in_google_photos(self):
        for command in ("clean", "copies"):
            with self.subTest(command=command):
                phone = self.fresh_phone()
                copies = [phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"), phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"photo")]
                phone.write_result({})

                phone.run(command, answers=["auto", "yes"])

                self.assertEqual(sum(os.path.exists(path) for path in copies), 1, msg="exactly one copy stays")

    # "auto" uses the suggestion for this file and all the next files, without more questions.
    def test_auto_uses_the_suggestion_for_all_next_files(self):
        contents = [f"photo {index}".encode() * (index + 1) for index in range(3)]
        whatsapp = [self.phone.add_whatsapp(f"WhatsApp Images/IMG-{index}.jpg", data) for index, data in enumerate(contents)]
        camera = [self.phone.add(f"DCIM/Camera/IMG_{index}.jpg", data) for index, data in enumerate(contents)]
        self.phone.write_result({})

        code, asked = self.phone.run("clean", answers=["auto", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 2, msg="after auto, only the last question is asked")
        self.assertFalse(any(os.path.exists(path) for path in whatsapp), msg="each WhatsApp copy is deleted, as suggested")
        self.assertTrue(all(os.path.exists(path) for path in camera), msg="each camera copy stays, as suggested")

    # "stop" keeps all copies of this file and the next files, but a file that is only in Google Photos is still deleted.
    def test_stop_keeps_the_copies_of_all_next_files(self):
        single = self.phone.add_whatsapp("WhatsApp Images/IMG-0.jpg", b"only copy, in google photos")
        copies = [self.phone.add_whatsapp(f"WhatsApp Images/IMG-{index}.jpg", f"photo {index}".encode()) for index in (1, 2)]
        copies += [self.phone.add(f"DCIM/Camera/IMG_{index}.jpg", f"photo {index}".encode()) for index in (1, 2)]
        self.phone.write_result({fingerprint_of(b"only copy, in google photos"): "AF1QipSingle"})

        code, asked = self.phone.run("clean", answers=["stop", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 2, msg="after stop, only the last question is asked")
        self.assertFalse(os.path.exists(single), msg="the file that is in Google Photos is deleted")
        self.assertTrue(all(os.path.exists(path) for path in copies), msg="every copy is kept")

    # Closing the input (or Ctrl+C) during the questions about copies stops at once and deletes nothing, also no file that is in Google Photos.
    def test_closing_the_input_during_the_questions_deletes_nothing(self):
        paths = [
            self.phone.add_whatsapp("WhatsApp Images/IMG-0.jpg", b"only copy, in google photos"),
            self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"),
            self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo"),
        ]
        self.phone.write_result({fingerprint_of(b"only copy, in google photos"): "AF1QipSingle"})

        for error in (EOFError, KeyboardInterrupt):
            with self.subTest(error=error.__name__):
                asked = []

                # Only the first question is interrupted. A later "yes" must not be asked for.
                def ask(prompt, error=error):
                    asked.append(prompt)
                    if len(asked) == 1:
                        raise error()
                    return "yes"

                code, _ = self.phone.run("clean", ask=ask)

                self.assertEqual(code, 1, msg="clean reports that it was cancelled")
                self.assertEqual(len(asked), 1, msg="no question is asked after the interruption")
                self.assertTrue(all(os.path.exists(path) for path in paths), msg="nothing is deleted")

    # After the questions about copies, any answer other than "yes" at the end deletes nothing.
    def test_no_at_the_end_deletes_nothing(self):
        copies = [self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo"), self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")]
        self.phone.write_result({})

        code, _ = self.phone.run("clean", answers=["1", "no"])

        self.assertEqual(code, 1, msg="clean reports that it was cancelled")
        self.assertTrue(all(os.path.exists(path) for path in copies), msg="nothing is deleted without a clear yes")

    # An answer that is not one of the choices asks the question again and chooses nothing.
    def test_an_unknown_answer_asks_again(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.write_result({})

        code, asked = self.phone.run("clean", answers=["maybe", "yes", "0", "3", "-1", "1.5", "", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 8, msg="each unknown answer asks the question again")
        self.assertFalse(os.path.exists(whatsapp), msg="Enter after the unknown answers uses the suggestion")
        self.assertTrue(os.path.exists(camera), msg="the suggested copy stays")

    # When the copy that is to stay changes or disappears before the deletion, the other copy is kept too.
    def test_copies_stay_when_the_copy_to_keep_changes(self):
        for change in ("edited", "deleted"):
            with self.subTest(change=change):
                phone = self.fresh_phone()
                whatsapp = phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
                camera = phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
                phone.write_result({})
                answers = ["", "yes"]

                def ask(_prompt, change=change, phone=phone, camera=camera, answers=answers):
                    answer = answers.pop(0)
                    if answer == "yes" and change == "edited":
                        phone.add("DCIM/Camera/IMG_1.jpg", b"edited photo")
                    elif answer == "yes":
                        os.remove(camera)
                    return answer

                code, _ = phone.run("clean", ask=ask)

                self.assertEqual(code, 0, msg="keeping files for safety is not an error")
                self.assertTrue(os.path.exists(whatsapp), msg="the WhatsApp copy is kept, because the copy that was to stay changed")

    # A copy that turns into a second name of the copy that stays is not deleted.
    def test_a_copy_that_became_the_copy_to_keep_is_not_deleted(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.write_result({})
        answers = ["", "yes"]

        def ask(_prompt):
            answer = answers.pop(0)
            if answer == "yes":
                os.remove(whatsapp)
                os.link(camera, whatsapp)
            return answer

        self.phone.run("clean", ask=ask)

        self.assertTrue(os.path.exists(whatsapp), msg="a name of the copy that stays is not deleted")
        self.assertEqual(self.phone.held_files(), [], msg="no file is moved")
        self.assertFalse(os.path.exists(self.phone.holding()), msg="no empty GPTK-deleted folder is left behind")

    # Copies in hidden, trash and app folders (Android/...) do not count, because they can disappear.
    def test_copies_in_hidden_trash_and_app_folders_do_not_count(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        places = (
            "DCIM/.thumbnails/IMG-1.jpg",
            "Pictures/.trashed-1700000000-IMG-1.jpg",
            "Pictures/Trash/IMG-1.jpg",
            "DCIM/RecycleBin/IMG-1.jpg",
            "Android/data/com.example.gallery/files/IMG-1.jpg",
            "Android/obb/com.example.game/IMG-1.jpg",
            "Android/media/org.telegram.messenger/Telegram/Telegram Images/IMG-1.jpg",
        )
        others = [self.phone.add(place, b"photo") for place in places]
        self.phone.write_result({})

        code, asked = self.phone.run("clean", answers=[])

        self.assertEqual(code, 0, msg="there is nothing to do")
        self.assertEqual(asked, [], msg="no copies are offered")
        self.assertTrue(all(os.path.exists(path) for path in [whatsapp, *others]), msg="nothing is deleted")

    # With --folder, a copy in a trash folder inside that folder is never the copy that stays, also when it is the oldest.
    def test_a_trash_folder_inside_the_chosen_folder_is_skipped(self):
        trash = self.phone.add("Pictures/Trash/IMG_1.jpg", b"photo")
        os.utime(trash, (time.time() - 86400 * 365, time.time() - 86400 * 365))
        copies = [self.phone.add("Pictures/IMG_1.jpg", b"photo"), self.phone.add("Pictures/Saved/IMG_1.jpg", b"photo")]

        code, _ = self.phone.run("copies", "--folder", "Pictures", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertTrue(any(os.path.exists(path) for path in copies), msg="a copy outside the trash folder stays on the phone")
        self.assertTrue(os.path.exists(trash), msg="the script does not touch files in a trash folder")

    # Another name of the same file (a hard link or a link) is not a copy.
    def test_links_are_not_copies(self):
        for kind, make_link in (("hard link", os.link), ("link", os.symlink)):
            with self.subTest(kind=kind):
                phone = self.fresh_phone()
                whatsapp = phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
                other = phone.path("DCIM/Camera/IMG_1.jpg")
                os.makedirs(os.path.dirname(other))
                make_link(whatsapp, other)
                phone.write_result({})

                code, asked = phone.run("clean", answers=[])

                self.assertEqual(code, 0, msg="there is nothing to do")
                self.assertEqual(asked, [], msg="no copies are offered")
                self.assertTrue(os.path.exists(whatsapp) and os.path.lexists(other), msg="nothing is deleted")

    # A file with the same size but other content is not a copy.
    def test_a_file_with_other_content_is_not_a_copy(self):
        paths = [self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo A"), self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo B")]
        self.phone.write_result({})

        code, asked = self.phone.run("clean", answers=[])

        self.assertEqual(code, 0, msg="there is nothing to do")
        self.assertEqual(asked, [], msg="no copies are offered")
        self.assertTrue(all(os.path.exists(path) for path in paths), msg="nothing is deleted")

    # Copies that are all outside WhatsApp are not offered, because only WhatsApp files are checked.
    def test_copies_outside_whatsapp_are_left_alone(self):
        paths = [
            self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo A"),
            self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo B"),
            self.phone.add("Download/IMG_1.jpg", b"photo B"),
        ]
        self.phone.write_result({})

        code, asked = self.phone.run("clean", answers=[])

        self.assertEqual(code, 0, msg="there is nothing to do")
        self.assertEqual(asked, [], msg="no copies are offered")
        self.assertTrue(all(os.path.exists(path) for path in paths), msg="nothing is deleted")

    # The list of moved files names the copy that stays on the phone for each moved copy.
    def test_moved_list_names_the_copy_that_stays(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.write_result({})

        self.phone.run("clean", answers=["", "yes"])

        self.assertEqual(
            [(entry["from"], entry["googlePhotos"], entry["keptCopy"]) for entry in self.phone.moved_list()],
            [(whatsapp, None, camera)],
            msg="the list shows the moved copy, no Google Photos link and the copy that stays",
        )

    # The copies command needs no Google Photos result, and by default the copy outside WhatsApp stays.
    def test_copies_command_needs_no_result(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")

        code, _ = self.phone.run("copies", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertFalse(os.path.exists(whatsapp), msg="the WhatsApp copy is deleted")
        self.assertTrue(os.path.exists(camera), msg="the camera copy stays on the phone")

    # Without a WhatsApp folder, the copies command stops and deletes nothing.
    def test_copies_command_without_folders_fails(self):
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.add("Download/IMG_1.jpg", b"photo")

        code, asked = self.phone.run("copies", answers=[])

        self.assertEqual(code, 2, msg="copies reports that it found no folder")
        self.assertEqual(asked, [], msg="the user is not asked")
        self.assertTrue(os.path.exists(camera), msg="nothing is deleted")


class SafetyNetTests(PhoneTestCase):
    """"yes" only moves the files to Download/GPTK-deleted. "undo" puts them back. "empty" deletes them for good."""

    def read(self, path: str) -> bytes:
        with open(path, "rb") as handle:
            return handle.read()

    # "yes" moves the files to GPTK-deleted, unchanged, in a folder that gallery apps do not show.
    def test_yes_moves_the_files_to_gptk_deleted(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        whatsapp = self.phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
        camera = self.phone.add("DCIM/Camera/VID_1.mp4", b"video")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        code, _ = self.phone.run("clean", answers=["", "yes"])

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertFalse(os.path.exists(backed_up) or os.path.exists(whatsapp), msg="the files are no longer in WhatsApp")
        self.assertEqual(self.phone.held_contents(), [b"in google photos", b"video"], msg="GPTK-deleted holds the moved files, unchanged")
        self.assertEqual(self.read(camera), b"video", msg="the copy that stays is not moved")
        self.assertTrue(os.path.isfile(os.path.join(self.phone.holding(), ".nomedia")), msg="gallery apps do not show the moved files")

    # "undo" puts every moved file back in its folder, with the same name, content and date, and removes GPTK-deleted.
    def test_undo_puts_every_file_back(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"in google photos")
        self.phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
        self.phone.add("DCIM/Camera/VID_1.mp4", b"video")
        for path in self.phone.snapshot():
            os.utime(path, (time.time() - 86400 * 100, time.time() - 86400 * 100))
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        before = self.phone.snapshot()
        self.phone.run("clean", answers=["", "", "yes"])
        self.assertEqual(len(self.phone.held_files()), 3, msg="test setup: clean moved 3 files")

        code, asked = self.phone.run("undo", answers=[])

        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual(asked, [], msg="undo asks nothing, because it deletes nothing")
        self.assertEqual(self.phone.snapshot(), before, msg="every file is back, with the same name, content and date")
        self.assertFalse(os.path.exists(self.phone.holding()), msg="the empty GPTK-deleted folder is removed")

    # "undo" never replaces a file: when a new file has the old name, the moved file stays in GPTK-deleted until the name is free.
    def test_undo_never_replaces_a_file(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean")
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"new photo with the same name")

        code, _ = self.phone.run("undo")

        self.assertEqual(code, 3, msg="undo reports the file that it could not put back")
        self.assertEqual(self.read(whatsapp), b"new photo with the same name", msg="the new file is not replaced")
        self.assertEqual(self.phone.held_contents(), [b"in google photos"], msg="the moved file is still safe in GPTK-deleted")

        os.remove(whatsapp)
        code, _ = self.phone.run("undo")

        self.assertEqual(code, 0, msg="undo succeeds when the name is free again")
        self.assertEqual(self.read(whatsapp), b"in google photos", msg="the moved file is back")

    # "undo" makes the folder of a moved file again when the folder was removed.
    def test_undo_makes_a_removed_folder_again(self):
        sent = self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean")
        os.rmdir(os.path.dirname(sent))

        code, _ = self.phone.run("undo")

        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual(self.read(sent), b"in google photos", msg="the file is back in its folder")

    # Without moved files, "undo" and "empty" do nothing and ask nothing.
    def test_undo_and_empty_without_moved_files_do_nothing(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        before = self.phone.snapshot()

        for command in ("undo", "empty"):
            with self.subTest(command=command):
                code, asked = self.phone.run(command, answers=[])

                self.assertEqual(code, 0, msg="there is simply nothing to do")
                self.assertEqual(asked, [], msg="the user is not asked")
                self.assertEqual(self.phone.snapshot(), before, msg="no file changes")

    # "empty" deletes nothing without a clear "yes", also when the question is closed.
    def test_empty_without_yes_deletes_nothing(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean")
        held = self.phone.held_files()

        for answer in ("", "y", "no", "yes please", EOFError, KeyboardInterrupt):
            with self.subTest(answer=str(answer)):

                def ask(_prompt, answer=answer):
                    if isinstance(answer, str):
                        return answer
                    raise answer()

                code, _ = self.phone.run("empty", ask=ask)

                self.assertEqual(code, 1, msg="empty reports that it was cancelled")
                self.assertEqual(self.phone.held_files(), held, msg="the moved files are still in GPTK-deleted")

    # "empty" with "yes" deletes the moved files for good, removes GPTK-deleted and touches no other file.
    def test_empty_deletes_the_moved_files_for_good(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
        self.phone.add("DCIM/Camera/VID_1.mp4", b"video")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean", answers=["", "yes"])
        rest = self.phone.snapshot()

        code, asked = self.phone.run("empty", answers=["yes"])

        self.assertEqual(code, 0, msg="empty succeeds")
        self.assertEqual(len(asked), 1, msg="empty asks once")
        self.assertFalse(os.path.exists(self.phone.holding()), msg="GPTK-deleted is gone, with the moved files")
        self.assertEqual(self.phone.snapshot(), rest, msg="no other file on the phone is touched")

    # "empty" keeps a moved file that Google Photos does not have when the copy that stayed on the phone changed or is gone. "undo" can still put it back.
    def test_empty_keeps_a_file_whose_other_copy_is_gone(self):
        for change in ("deleted", "edited"):
            with self.subTest(change=change):
                phone = self.fresh_phone()
                whatsapp = phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
                camera = phone.add("DCIM/Camera/VID_1.mp4", b"video")
                phone.run("copies", answers=["", "yes"])
                if change == "deleted":
                    os.remove(camera)
                else:
                    phone.add("DCIM/Camera/VID_1.mp4", b"edited video")

                code, _ = phone.run("empty", answers=["yes"])

                self.assertEqual(code, 0, msg="keeping a file for safety is not an error")
                self.assertEqual(phone.held_contents(), [b"video"], msg="the last copy of the video is not deleted")
                phone.run("undo")
                self.assertEqual(self.read(whatsapp), b"video", msg="undo puts the last copy back")

    # "empty" deletes a moved file that is in Google Photos also when its copy on the phone is gone, because Google Photos keeps it.
    def test_empty_deletes_a_google_photos_file_when_its_phone_copy_is_gone(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.write_result({fingerprint_of(b"photo"): "AF1QipPhoto"})
        self.phone.run("clean", answers=["", "yes"])
        os.remove(camera)

        code, _ = self.phone.run("empty", answers=["yes"])

        self.assertEqual(code, 0, msg="empty succeeds")
        self.assertEqual(self.phone.held_files(), [], msg="the file that Google Photos has is deleted")

    # "empty" keeps a file in GPTK-deleted that changed after it was moved.
    def test_empty_keeps_a_moved_file_that_changed(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first photo")
        self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second photo")
        self.phone.write_result({fingerprint_of(b"first photo"): "AF1QipFirst", fingerprint_of(b"second photo"): "AF1QipSecond"})
        self.phone.run("clean")
        batch, name, _ = next(item for item in self.phone.held_files() if item[2] == b"first photo")
        with open(os.path.join(self.phone.holding(), batch, name), "wb") as handle:
            handle.write(b"other photo")

        code, _ = self.phone.run("empty", answers=["yes"])

        self.assertEqual(code, 0, msg="keeping a file for safety is not an error")
        self.assertEqual(self.phone.held_contents(), [b"other photo"], msg="only the unchanged file is deleted")

    # Files in GPTK-deleted are never copies, so the copy that the user chose to keep is not offered again.
    def test_moved_files_are_not_copies(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.run("copies", answers=["1", "yes"])
        self.assertTrue(os.path.exists(whatsapp) and not os.path.exists(camera), msg="test setup: the WhatsApp copy stays, the camera copy is moved")

        code, asked = self.phone.run("copies", answers=[])

        self.assertEqual(code, 0, msg="there is nothing to do")
        self.assertEqual(asked, [], msg="the moved copy is not offered as a copy")
        self.assertEqual(self.read(whatsapp), b"photo", msg="the copy that the user kept stays")

    # The files in GPTK-deleted are never read, also when --folder names Download or a folder in GPTK-deleted.
    def test_gptk_deleted_is_never_read(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean")
        held = self.phone.held_files()

        code, _ = self.phone.run("scan", "--folder", "Download")

        self.assertEqual(code, 0, msg="scan succeeds")
        self.assertEqual(self.phone.fingerprints(), [], msg="the moved files are not read in Download")
        for folder in ("Download/GPTK-deleted", "Download/gptk-deleted", f"Download/GPTK-deleted/{held[0][0]}"):
            with self.subTest(folder=folder):
                code, asked = self.phone.run("copies", "--folder", folder, answers=[])

                self.assertEqual(code, 2, msg="a folder in GPTK-deleted is refused")
                self.assertEqual(asked, [], msg="the user is not asked")
        self.assertEqual(self.phone.held_files(), held, msg="the moved files are not touched")

    # Two moves in the same second keep their files apart, and "undo" puts back the files of both.
    def test_two_moves_in_the_same_second_are_both_undone(self):
        first = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first photo")
        frozen = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)

        class FrozenClock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return frozen.astimezone(tz) if tz is not None else frozen.replace(tzinfo=None)

        with mock.patch.object(phone.dt, "datetime", FrozenClock):
            self.phone.write_result({fingerprint_of(b"first photo"): "AF1QipFirst"})
            self.phone.run("clean")
            second = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second photo")
            self.phone.write_result({fingerprint_of(b"second photo"): "AF1QipSecond"})
            self.phone.run("clean")
        self.assertEqual(len(self.phone.batches()), 2, msg="each yes has its own folder in GPTK-deleted")

        code, _ = self.phone.run("undo")

        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual((self.read(first), self.read(second)), (b"first photo", b"second photo"), msg="the files of both moves are back")

    # Files with the same name from different folders are kept apart in GPTK-deleted, and "undo" puts each back in its own folder.
    def test_files_with_the_same_name_are_kept_apart(self):
        files = {
            self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo A"): b"photo A",
            self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"photo B"): b"photo B",
            self.phone.add_whatsapp("WhatsApp Images/Private/img-1.JPG", b"photo C"): b"photo C",
            self.phone.add_whatsapp("WhatsApp Images/caf\u00e9.jpg", b"photo D"): b"photo D",
            self.phone.add_whatsapp("WhatsApp Images/Sent/cafe\u0301.jpg", b"photo E"): b"photo E",
        }
        self.phone.write_result({fingerprint_of(content): f"AF1Qip{index}" for index, content in enumerate(files.values())})
        self.phone.run("clean")

        names = [name for _, name, _ in self.phone.held_files()]
        same_name = [unicodedata.normalize("NFD", name).casefold() for name in names]
        self.assertEqual(len(set(same_name)), len(files), msg="the names differ also on a phone that ignores upper and lower case and the form of letters")
        code, _ = self.phone.run("undo")

        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual({path: self.read(path) for path in files}, files, msg="each file is back in its own folder")

    # When the script stops while files move (Ctrl+C, or the phone closes Termux), "undo" still puts back every file that moved.
    def test_undo_works_after_a_stop_while_files_move(self):
        class PhoneStopped(BaseException):
            """The phone stops the script at once, with no time to tidy up."""

        for stop in (KeyboardInterrupt, PhoneStopped):
            with self.subTest(stop=stop.__name__):
                device = self.fresh_phone()
                contents = [b"first photo", b"second photo", b"third photo"]
                for index, content in enumerate(contents):
                    device.add_whatsapp(f"WhatsApp Images/IMG-{index}.jpg", content)
                device.write_result({fingerprint_of(content): f"AF1Qip{index}" for index, content in enumerate(contents)})
                before = device.snapshot()
                real_rename = os.rename
                moves = []

                # The second file moves, and then the stop comes at once.
                def rename(source, target, stop=stop):
                    moves.append(source)
                    real_rename(source, target)
                    if len(moves) == 2:
                        raise stop()

                with mock.patch.object(phone.os, "rename", side_effect=rename):
                    try:
                        device.run("clean")
                    except PhoneStopped:
                        pass
                self.assertEqual(len(device.held_files()), 2, msg="test setup: two files moved before the stop")

                code, _ = device.run("undo")

                self.assertEqual(code, 0, msg="undo succeeds")
                self.assertEqual(device.snapshot(), before, msg="every file that moved is back")

    # A stop while the list of moved files is saved (Ctrl+C, or the phone ends Termux at once) loses nothing, and "undo" cleans up.
    @unittest.skipUnless(hasattr(os, "fork"), "needs os.fork to stop the script at once")
    def test_a_stop_while_the_list_is_saved_loses_nothing(self):
        for save, stop in ((1, "at once"), (2, "at once"), (2, "Ctrl+C")):
            with self.subTest(save=save, stop=stop):
                device = self.fresh_phone()
                device.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
                device.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
                device.add("DCIM/Camera/VID_1.mp4", b"video")
                device.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
                before = device.snapshot()
                real_replace = os.replace
                saves = []

                # The list is saved before the files move and again after. The stop comes during the chosen save.
                def replace(source, target, save=save, stop=stop):
                    saves.append(target)
                    if len(saves) == save and stop == "Ctrl+C":
                        raise KeyboardInterrupt()
                    if len(saves) == save:
                        os._exit(9)
                    real_replace(source, target)

                def clean(device=device, replace=replace):
                    with mock.patch.object(phone.os, "replace", side_effect=replace):
                        return device.run("clean", answers=["", "yes"])[0]

                if stop == "Ctrl+C":
                    try:
                        code = clean()
                    except KeyboardInterrupt:
                        code = None
                    self.assertEqual(code, 1, msg="clean ends normally and reports that it was stopped")
                else:
                    child = os.fork()
                    if child == 0:
                        try:
                            clean()
                        finally:
                            os._exit(0)
                    _, status = os.waitpid(child, 0)
                    self.assertEqual(os.waitstatus_to_exitcode(status), 9, msg="test setup: the script stopped while it saved the list")

                code, _ = device.run("undo")

                self.assertEqual(code, 0, msg="undo succeeds")
                self.assertEqual(device.snapshot(), before, msg="every file is back, unchanged")
                self.assertFalse(os.path.exists(device.holding()), msg="nothing is left in GPTK-deleted")

    # A short read error just after a file moves does not drop the file from the list, so "undo" still puts it back.
    def test_a_read_error_after_a_move_does_not_lose_the_file(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        before = self.phone.snapshot()
        real_lstat = os.lstat
        errors = []

        # The first look at a file in GPTK-deleted fails once, like a short storage error.
        def lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if not errors and os.fspath(path).startswith(self.phone.holding()) and stat.S_ISREG(info.st_mode):
                errors.append(path)
                raise OSError(errno.EIO, "Input/output error")
            return info

        with mock.patch.object(phone.os, "lstat", side_effect=lstat):
            self.phone.run("clean")
        self.assertEqual(len(errors), 1, msg="test setup: one read error happened")

        code, _ = self.phone.run("undo")

        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual(self.phone.snapshot(), before, msg="the moved file is back")

    # A relative phone storage path (for example "storage/shared" in Termux) also works with "undo".
    def test_undo_works_with_a_relative_storage_path(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        before = self.phone.snapshot()
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(os.path.dirname(self.phone.root))
        relative = os.path.basename(self.phone.root)

        with contextlib.redirect_stdout(io.StringIO()):
            moved = phone.main(["clean", "--storage", relative], ask=lambda _prompt: "yes")
            code = phone.main(["undo", "--storage", relative], ask=lambda _prompt: "")

        self.assertEqual(moved, 0, msg="test setup: clean succeeds")
        self.assertEqual(code, 0, msg="undo succeeds")
        self.assertEqual(self.phone.snapshot(), before, msg="the moved file is back")

    # When two moves name the same copy that stays, each time with another content, "empty" deletes only the moved file whose content that copy still has.
    def test_empty_checks_the_copy_that_stays_for_each_content(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first version")
        saved = self.phone.add("Pictures/photo.jpg", b"first version")
        self.phone.run("copies", answers=["", "yes"])
        self.phone.add("Pictures/photo.jpg", b"second version")
        self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second version")
        self.phone.run("copies", answers=["", "yes"])
        self.assertEqual(self.phone.held_contents(), [b"first version", b"second version"], msg="test setup: one file of each version moved")
        self.phone.add("Pictures/photo.jpg", b"first version")

        code, _ = self.phone.run("empty", answers=["yes"])

        self.assertEqual(code, 0, msg="keeping files for safety is not an error")
        self.assertEqual(self.phone.held_contents(), [b"second version"], msg="the second version stays, because no other copy of it is on the phone")
        self.assertEqual(self.read(saved), b"first version", msg="the copy that stays is not touched")

    # "empty" never trusts a file in GPTK-deleted as the copy that stays, also when a damaged list names one, because that copy can be deleted too.
    def test_empty_never_counts_a_moved_file_as_the_copy_that_stays(self):
        for named in ("itself", "itself through a link", "another moved copy"):
            with self.subTest(named=named):
                device = self.fresh_phone()
                device.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
                device.add_whatsapp("WhatsApp Video/Sent/VID-1.mp4", b"video")
                camera = device.add("DCIM/Camera/VID_1.mp4", b"video")
                device.run("copies", answers=["", "yes"])
                os.remove(camera)
                (batch, first, _), (_, second, _) = device.held_files()
                if named == "itself":
                    kept = os.path.join(device.holding(), batch, first)
                elif named == "itself through a link":
                    os.symlink(os.path.join(device.holding(), batch), device.path("Pictures"))
                    kept = os.path.join(device.path("Pictures"), first)
                else:
                    kept = os.path.join(device.holding(), batch, second)
                list_path = os.path.join(device.holding(), batch, "moved-files.json")
                with open(list_path, encoding="utf-8") as handle:
                    content = json.load(handle)
                for entry in content["files"]:
                    if entry["name"] == first:
                        entry["keptCopy"] = kept
                with open(list_path, "w", encoding="utf-8") as handle:
                    json.dump(content, handle)

                code, _ = device.run("empty", answers=["yes"])

                self.assertEqual(code, 0, msg="keeping files for safety is not an error")
                self.assertEqual(device.held_contents(), [b"video", b"video"], msg="no moved copy is deleted, because no copy stays outside GPTK-deleted")

    # When the list of moved files is damaged, "undo" and "empty" touch no file in that folder.
    def test_a_damaged_list_leaves_the_files_alone(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})
        self.phone.run("clean")
        held = self.phone.held_files()
        list_path = os.path.join(self.phone.holding(), held[0][0], "moved-files.json")
        with open(list_path, encoding="utf-8") as handle:
            good = json.load(handle)
        damages = {
            "not JSON": "{",
            "another type": json.dumps(dict(good, type="fingerprints")),
            "a name with a folder": json.dumps(dict(good, files=[dict(good["files"][0], name="../IMG-1.jpg")])),
            "a place that is not a full path": json.dumps(dict(good, files=[dict(good["files"][0], **{"from": "IMG-1.jpg"})])),
            "a bad fingerprint": json.dumps(dict(good, files=[dict(good["files"][0], hash="not a fingerprint")])),
        }

        for damage, text in damages.items():
            with self.subTest(damage=damage):
                with open(list_path, "w", encoding="utf-8") as handle:
                    handle.write(text)

                undo_code, _ = self.phone.run("undo")
                empty_code, asked = self.phone.run("empty", answers=["yes"])

                self.assertEqual((undo_code, empty_code), (2, 2), msg="undo and empty report the damaged list")
                self.assertEqual(asked, [], msg="empty does not offer to delete files without a good list")
                self.assertEqual(self.phone.held_files(), held, msg="the files in that folder are not touched")


class RandomPhoneTests(PhoneTestCase):
    """Many random phones, random answers and files that change meanwhile: no photo or video is ever lost."""

    WHATSAPP_PLACES = (
        f"{WHATSAPP_MEDIA}/WhatsApp Images",
        f"{WHATSAPP_MEDIA}/WhatsApp Images/Sent",
        f"{WHATSAPP_MEDIA}/WhatsApp Video",
        "WhatsApp/Media/WhatsApp Images",
        "storage-0/Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Video",
        "Pictures/WhatsApp",
    )
    OTHER_PLACES = ("DCIM/Camera", "Pictures", "Pictures/Saved", "Download")
    UNTOUCHABLE_PLACES = (
        f"{WHATSAPP_MEDIA}/WhatsApp Stickers",
        f"{WHATSAPP_MEDIA}/.Statuses",
        "DCIM/.thumbnails",
        "DCIM/.hidden/WhatsApp",
        "Pictures/Trash",
        "Android/data/com.example.gallery/files",
        "Android/data/com.whatsapp/files",
    )
    NAMES = ("IMG-1.jpg", "img-1.JPG", "VID-1.mp4", "caf\u00e9.jpg", "cafe\u0301.jpg", "photo (2).jpg", ".hidden.jpg", "notes.txt")
    # Two photos of the same size, so that a file with the same size is not always a copy.
    CONTENTS = (b"photo A", b"photo B", b"video C" * 9, b"video D" * 9, b"photo E" * 3, b"")
    ANSWERS = ("", "", "", "1", "1", "2", "2", "3", "all", " ALL ", "skip", "auto", "stop", "maybe")

    def random_phone(self, rng) -> FakePhone:
        phone = self.fresh_phone()
        used = set()
        places = self.WHATSAPP_PLACES + self.OTHER_PLACES + self.UNTOUCHABLE_PLACES
        for index in range(rng.randint(6, 22)):
            relative = f"{rng.choice(self.WHATSAPP_PLACES if index == 0 else places)}/{rng.choice(self.NAMES)}"
            # On the phone, names that differ only in upper and lower case or in the form of a letter are one file.
            key = unicodedata.normalize("NFD", relative).casefold()
            if key not in used:
                used.add(key)
                path = phone.add(relative, rng.choice(self.CONTENTS))
                moment = time.time() - rng.randint(0, 86400 * 400)
                os.utime(path, (moment, moment))
        return phone

    def change_randomly(self, rng, phone) -> None:
        """Edits, replaces or deletes a few files, as if the phone was used while the last question was open."""
        paths = sorted(phone.snapshot())
        for path in rng.sample(paths, min(len(paths), rng.choice((0, 0, 1, 2)))):
            action = rng.choice(("edit", "replace", "delete"))
            if action == "delete":
                os.remove(path)
            else:
                with open(path, "wb") as handle:
                    handle.write(b"edited" if action == "edit" else rng.choice(self.CONTENTS))

    def run_randomly(self, rng, phone, command) -> dict:
        """Runs the command with random answers, but never confirms deleting every copy of a file. Returns the phone just before the move."""
        seen = {"before": phone.snapshot()}

        def ask(prompt):
            if "choice" in prompt.lower():
                return rng.choice(self.ANSWERS)
            if '"delete"' in prompt:
                return ""
            self.change_randomly(rng, phone)
            seen["before"] = phone.snapshot()
            return "yes"

        code, _ = phone.run(command, ask=ask)
        self.assertEqual(code, 0, msg="the command ends normally")
        return seen["before"]

    def check_move(self, phone, before, google) -> int:
        """Checks the phone after the move. Returns the number of moved files."""
        after = phone.snapshot()
        held = {(batch, name): content for batch, name, content in phone.held_files()}
        moved = sorted(set(before) - set(after))
        self.assertLessEqual(set(after), set(before), msg="no new file appears outside GPTK-deleted")
        self.assertEqual({path: before[path] for path in after}, after, msg="no file that stays is changed")
        self.assertEqual(sorted(before[path][0] for path in moved), sorted(held.values()), msg="GPTK-deleted holds exactly the moved files, unchanged")
        entries = phone.moved_list()
        self.assertEqual(sorted(entry["from"] for entry in entries), moved, msg="the list names each moved file")
        for entry in entries:
            self.assertEqual(held[(entry["batch"], entry["name"])], before[entry["from"]][0], msg="the list knows where each moved file was")
        for path in moved:
            relative = os.path.relpath(path, phone.root)
            self.assertIn(os.path.dirname(relative), self.WHATSAPP_PLACES + self.OTHER_PLACES, msg="files in hidden, trash, sticker and app folders never move")
            self.assertFalse(os.path.basename(path).startswith(".") or path.endswith(".txt"), msg="only photos and videos that are not hidden move")
        left = {content for content, _ in after.values()}
        for content, _ in before.values():
            self.assertTrue(content in left or fingerprint_of(content) in google, msg="each photo and video is still on the phone or in Google Photos")
        return len(moved)

    def check_empty(self, rng, phone, google) -> tuple:
        """Deletes some files, then empties GPTK-deleted and checks the phone. Returns the numbers of deleted and kept files."""
        entries = phone.moved_list()
        for entry in entries:
            if entry["keptCopy"] and os.path.exists(entry["keptCopy"]) and rng.random() < 0.5:
                os.remove(entry["keptCopy"])
        before = phone.snapshot()
        held = phone.held_files()

        code, _ = phone.run("empty", answers=["yes"])

        after = phone.snapshot()
        remaining = phone.held_files()
        self.assertEqual(code, 0, msg="empty ends normally")
        self.assertEqual(after, before, msg="empty touches no file outside GPTK-deleted")
        everything = {content for content, _ in after.values()} | {content for _, _, content in remaining}
        for content in [content for content, _ in before.values()] + [content for _, _, content in held]:
            self.assertTrue(content in everything or fingerprint_of(content) in google, msg="empty never deletes the last copy of a file that Google Photos does not have")
        for batch, name, content in remaining:
            entry = next(entry for entry in entries if (entry["batch"], entry["name"]) == (batch, name))
            other_copy = before.get(entry["keptCopy"])
            self.assertIsNone(entry["googlePhotos"], msg="a file that Google Photos has is always deleted")
            self.assertTrue(other_copy is None or other_copy[0] != content, msg="a file stays only when the copy that stayed on the phone is gone or changed")
        return len(held) - len(remaining), len(remaining)

    # Whatever the answers and changes, no photo or video is lost, "undo" puts everything back and "empty" keeps every last copy.
    def test_random_phones_never_lose_a_photo(self):
        totals = {"moved": 0, "deleted": 0, "kept": 0}
        for seed in range(60):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                phone = self.random_phone(rng)
                command = "copies" if seed % 2 == 0 else "clean"
                google = {}
                if command == "clean":
                    google = {fingerprint_of(content): f"AF1QipRandom{index}" for index, content in enumerate(self.CONTENTS) if rng.random() < 0.4}
                    phone.write_result(google)

                before = self.run_randomly(rng, phone, command)
                totals["moved"] += self.check_move(phone, before, google)
                code, _ = phone.run("undo", answers=[])

                self.assertEqual(code, 0, msg="undo succeeds")
                self.assertEqual(phone.snapshot(), before, msg="undo puts every file back as it was")
                self.assertFalse(os.path.exists(phone.holding()), msg="GPTK-deleted is removed")

                before = self.run_randomly(rng, phone, command)
                totals["moved"] += self.check_move(phone, before, google)
                deleted, kept = self.check_empty(rng, phone, google)
                totals["deleted"] += deleted
                totals["kept"] += kept
        self.assertTrue(all(totals.values()), msg=f"the random phones moved, deleted and kept files: {totals}")


if __name__ == "__main__":
    unittest.main()
