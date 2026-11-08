"""Tests for gptk_phone_check.py. Run: python3 -m unittest discover -s tools/phone-check -v"""

import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import tempfile
import time
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

    def records(self) -> list:
        """Rows (path, size, Google Photos link, copy that stays) of every gptk-deleted-*.txt file."""
        rows = []
        for name in sorted(os.listdir(self.downloads)):
            if name.startswith("gptk-deleted-"):
                with open(os.path.join(self.downloads, name), encoding="utf-8") as handle:
                    rows += [line.rstrip("\n").split("\t") for line in handle if not line.startswith("#")]
        return rows


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

    # With --folder, only that folder is scanned.
    def test_scan_uses_only_the_chosen_folder(self):
        self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"whatsapp photo")
        self.phone.add("DCIM/Test/photo.jpg", b"test photo")

        self.phone.run("scan", "--folder", "DCIM/Test")

        self.assertEqual(self.phone.fingerprints(), [fingerprint_of(b"test photo")], msg="only the chosen folder is read")

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

    # The record lists every deleted file with its Google Photos link.
    def test_clean_records_deleted_files(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"only on the phone")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        self.phone.run("clean")

        self.assertEqual(
            self.phone.records(),
            [[backed_up, str(len(b"in google photos")), "https://photos.google.com/photo/AF1QipBackedUp", ""]],
            msg="the record shows the deleted file, its size, where it is in Google Photos and that no copy stays on the phone",
        )

    # When the phone refuses to delete a file, the other files are still deleted and clean reports the problem.
    def test_clean_reports_files_it_could_not_delete(self):
        locked = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"first photo")
        free = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"second photo")
        self.phone.write_result({fingerprint_of(b"first photo"): "AF1QipFirst", fingerprint_of(b"second photo"): "AF1QipSecond"})
        real_remove = os.remove

        def remove(path):
            if path == locked:
                raise PermissionError("not allowed")
            real_remove(path)

        with mock.patch.object(phone.os, "remove", side_effect=remove):
            code, _ = self.phone.run("clean")

        self.assertEqual(code, 3, msg="clean reports that some files could not be deleted")
        self.assertTrue(os.path.exists(locked), msg="the refused file is still there")
        self.assertFalse(os.path.exists(free), msg="the other file is deleted")
        self.assertEqual([row[0] for row in self.phone.records()], [free], msg="the record lists only files that were really deleted")

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

    # The suggestion keeps a copy in a gallery folder rather than one in Download, which is often emptied.
    def test_suggestion_prefers_a_gallery_folder_to_download(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Video/VID-1.mp4", b"video")
        download = self.phone.add("Download/VID-1.mp4", b"video")
        gallery = self.phone.add("Pictures/Saved/funny video.mp4", b"video")

        code, _ = self.phone.run("copies", answers=["", "yes"])

        self.assertEqual(code, 0, msg="copies succeeds")
        self.assertTrue(os.path.exists(gallery), msg="the copy in the gallery folder stays")
        self.assertFalse(os.path.exists(download) or os.path.exists(whatsapp), msg="the other copies are deleted")

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
        self.assertEqual(self.phone.records(), [], msg="the record lists no deleted file")

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

    # The record names the copy that stays on the phone for each deleted copy.
    def test_record_names_the_copy_that_stays(self):
        whatsapp = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"photo")
        camera = self.phone.add("DCIM/Camera/IMG_1.jpg", b"photo")
        self.phone.write_result({})

        self.phone.run("clean", answers=["", "yes"])

        self.assertEqual(
            self.phone.records(),
            [[whatsapp, str(len(b"photo")), "", camera]],
            msg="the record shows the deleted copy, its size, no Google Photos link and the copy that stays",
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


if __name__ == "__main__":
    unittest.main()
