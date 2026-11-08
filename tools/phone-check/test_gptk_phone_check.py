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

    def run(self, *args, answer: str = "yes", ask=None):
        asked = []

        def default_ask(prompt):
            asked.append(prompt)
            return answer

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
        """Rows (path, size, link) of every gptk-deleted-*.txt file."""
        rows = []
        for name in sorted(os.listdir(self.downloads)):
            if name.startswith("gptk-deleted-"):
                with open(os.path.join(self.downloads, name), encoding="utf-8") as handle:
                    rows += [line.rstrip("\n").split("\t") for line in handle if not line.startswith("#")]
        return rows


class PhoneTestCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.phone = FakePhone(temp.name)


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
    # After "yes", every copy of a file that is in Google Photos is deleted, and nothing else.
    def test_clean_deletes_only_files_in_google_photos(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        backed_up_copy = self.phone.add_whatsapp("WhatsApp Images/Sent/IMG-1.jpg", b"in google photos")
        phone_only = self.phone.add_whatsapp("WhatsApp Images/IMG-2.jpg", b"only on the phone")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        code, asked = self.phone.run("clean", answer="yes")

        self.assertEqual(code, 0, msg="clean succeeds")
        self.assertEqual(len(asked), 1, msg="the user is asked once before deleting")
        self.assertFalse(os.path.exists(backed_up), msg="the backed-up file is deleted")
        self.assertFalse(os.path.exists(backed_up_copy), msg="its copy is deleted too")
        self.assertTrue(os.path.exists(phone_only), msg="a file that is not in Google Photos is kept")

    # Any answer other than "yes" deletes nothing.
    def test_clean_keeps_everything_without_yes(self):
        backed_up = self.phone.add_whatsapp("WhatsApp Images/IMG-1.jpg", b"in google photos")
        self.phone.write_result({fingerprint_of(b"in google photos"): "AF1QipBackedUp"})

        for answer in ["", "y", "no", "yes please"]:
            with self.subTest(answer=answer):
                code, _ = self.phone.run("clean", answer=answer)

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
            [[backed_up, str(len(b"in google photos")), "https://photos.google.com/photo/AF1QipBackedUp"]],
            msg="the record shows the deleted file, its size and where it is in Google Photos",
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


if __name__ == "__main__":
    unittest.main()
