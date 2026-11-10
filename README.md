# Google Photos Toolkit

Bulk organize your media

![demo](media/demo.png)

## How It Works

In your browser, utilizing GP's undocumented web api

## How To Install

1. Install [Tampermonkey](https://www.tampermonkey.net/) userscript manager for your browser
   - If you're on Android, try [Firefox](https://www.mozilla.org/firefox/browsers/mobile/android/), it supports Tampermonkey
2. Click [Install](https://github.com/iCloud17/Google-Photos-Toolkit/releases/latest/download/google_photos_toolkit.user.js)
3. Accept installation

### Finding space-consuming media

This example groups all space-consuming media in one album.

1. Make sure "Library" is the selected source
2. Select `SPACE-CONSUMING` in the `Space` filter
3. Select action `Add to new album`

### Identify media not in any albums

Select all albums in the `Exclude albums` filter, then use appropriate action.

### Identifying duplicates/similar images

Use `Similarity` filter with action `Add to new album`
Media with similar thumbnails will be added to the album.

### Deleting all media in the library

As simple as selecting "Library" source, clicking `Move to trash`, then clearing it.

### Freeing phone space (Phone Check)

Phone Check finds photos and videos on your Android phone (for example, in the WhatsApp folder) that are already in your Google Photos, and extra copies of them in other folders of the phone. Then a small script moves only the files that you choose to a holding folder. From there, you can put them back, or delete them for good.

Safety and privacy:

- The phone script ([`tools/phone-check/gptk_phone_check.py`](tools/phone-check/gptk_phone_check.py)) uses only the Python standard library. It does not connect to the internet.
- GPTK sends only fingerprints (SHA-1 hashes) to Google Photos, in your own logged-in session. It does not send files or file names. Phone Check changes nothing in Google Photos.
- A file counts as "already in Google Photos" only if Google Photos has an identical copy in Original quality that is saved in your library, fully uploaded, and not in the Trash. If GPTK cannot check a file, the file stays on the phone.
- For each file that has more than one copy on the phone, the script shows the name, date and folder of every copy, and you choose what stays. A file that is not confirmed in Google Photos always keeps 1 copy on the phone, unless you type `all` and then `delete` for that file.
- The script moves nothing until you type `yes`. Just before it moves a file, it reads the file again (and the copy that stays) to make sure that nothing changed.
- `yes` does not delete. It moves the files to `Download/GPTK-deleted/<date and time>/`, together with `moved-files.json`: the list of where each file was, its Google Photos link, and the copy that stays. Gallery apps do not show this folder, and the script never counts a file in it as a copy.
- `undo` puts the moved files back where they were, with their dates. It never replaces a file. `empty` asks for `yes`, then deletes the moved files for good. It deletes a file that is not in Google Photos only if the copy that stays is still on the phone and unchanged. Otherwise it keeps the file, so that `undo` can put it back. Use `empty` instead of deleting the folder yourself.

You need, on the phone: Firefox with Violentmonkey (or Tampermonkey) and GPTK, and [Termux](https://termux.dev) from F-Droid or GitHub.

1. In Termux, run `termux-setup-storage` and allow file access ("All files access" on Android 11 and later).
2. Run `pkg upgrade`, then `pkg install python curl`. Termux packages must all be upgraded together: if `curl` stops with "CANNOT LINK EXECUTABLE", run `apt update && apt full-upgrade`, then try again. Then download the script: `curl -L -o gptk_phone_check.py https://raw.githubusercontent.com/iCloud17/Google-Photos-Toolkit/main/tools/phone-check/gptk_phone_check.py`
3. Run `python gptk_phone_check.py scan`. It writes `Download/gptk-fingerprints.json`.
4. In Firefox, open photos.google.com, open GPTK, then open `Phone Check`. Choose `gptk-fingerprints.json`, tap `Check`, then tap `Download Result`. Always download the result, also when nothing is found, so that it replaces any older result.
5. In Termux, run `python gptk_phone_check.py clean`. The result file is valid for 2 days, and only for the last scan. If you scan again, check the new `gptk-fingerprints.json` in GPTK again.
6. The script looks for copies in the other folders of the phone (this can take a few minutes). For each file with more than one copy, type one of these answers:
   - a copy number: keep only that copy and delete the other copies.
   - `all`: delete all copies. If Google Photos does not have the file, you must also type `delete`.
   - `skip`: keep all copies.
   - `auto`: use the suggestion for this file and all the next files.
   - `stop`: keep all copies of this file and all the next files.
   - Enter: use the suggestion. It keeps a copy outside WhatsApp if there is one (not in Download if possible, then the oldest). It deletes all copies only if Google Photos has the file and all copies are in WhatsApp.
7. Read the summary, then type `yes` to move the files to `Download/GPTK-deleted`. They still use space on the phone.
8. Check your photos and WhatsApp chats. To put all the files back, run `python gptk_phone_check.py undo`.
9. When you are sure, run `python gptk_phone_check.py empty` and type `yes`. This deletes the moved files for good and frees the space.

To look only for copies, without Google Photos (no steps 3 and 4), run `python gptk_phone_check.py copies`. Steps 7 to 9 are the same.

Options: `--folder "Pictures/Screenshots"` checks a different folder (relative to the phone storage, can be repeated). Use the same `--folder` options for `scan` and `clean`. `--list` (for `clean` and `copies`) shows each file before you confirm. To try it safely first, use a small test folder.

Limits:

- Only identical copies are found. Edited or re-saved copies are not found, so they stay on the phone.
- Copies are searched only in the internal storage, not on an SD card. The script skips hidden files and folders and trash and recycle bin folders everywhere (also in the WhatsApp or `--folder` folders). In the other folders, it does not search app folders (`Android/...`), because an app can delete its files at any time.
- If a file is not confirmed in Google Photos and all its copies are in WhatsApp (for example, the same photo in 2 chats), the suggestion keeps 1 copy in WhatsApp. If you then delete that chat with its media, or uninstall WhatsApp, the file is gone. The summary before `yes` shows how many files this applies to. To keep all copies of a file, type `skip`.
- Files whose Google Photos copy is in Storage saver quality stay on the phone, because that copy is smaller than the original.
- After you move or delete WhatsApp media, WhatsApp chats show it as not available. The copies stay in Google Photos.
- If Google Photos already backs up the folder, the Google Photos app's "Free up space" can do a similar cleanup.
- Phone Check uses Google Photos' undocumented web API. If Google changes it, Phone Check most likely shows "Could not check" and the script moves nothing.

Tests: `pnpm test` (includes an end-to-end test with the Python script) and `pnpm test:phone-script`.

### Use GPTK's api

GPTK exports it's api class globally so you can use it in your browser's console.  
It's much more powerful than the UI!

Example usage.
Scan the whole library for media owned by `ownerName` and move it to trash if found.

```js
let nextPageId = null;
const ownerName = 'John';
do {
  const page = await gptkApi.getItemsByUploadedDate(nextPageId);
  for (const item of page.items) {
    if (item.isOwned) continue;
    const itemInfo = await gptkApi.getItemInfoExt(item.mediaKey);
    console.log(`${item.mediaKey} is shared by ${itemInfo.owner.name}`);
    if (itemInfo.owner.name == ownerName) {
      await gptkApi.moveItemsToTrash([itemInfo.dedupKey]);
      console.log(`${item.mediaKey} moved to trash`);
    }
  }
  nextPageId = page.nextPageId;
} while (nextPageId);
console.log('DONE');
```

## Contributions welcome

If you want to learn more about how GP's api works, read [https://kovatch.medium.com/deciphering-google-batchexecute-74991e4e446c](https://kovatch.medium.com/deciphering-google-batchexecute-74991e4e446c)  
I just found this post, after doing all the work from zero :D

Also, i've made a userscript that parses all responses and logs them to console in a more readable way, you can find it here - [https://github.com/xob0t/Google-Photos-Toolkit/tree/main/tools](https://github.com/xob0t/Google-Photos-Toolkit/tree/main/tools)

## BUGS

If something does not work, open an [issue](https://github.com/xob0t/Google-Photos-Toolkit/issues) and describe it in detail

If you have a question, open a [discussion](https://github.com/xob0t/Google-Photos-Toolkit/discussions)

## Credits

Borrowed some code and UI inspiration from [undiscord](https://github.com/victornpb/undiscord)

## My Other Google Photos Projects

- Python client with unlimited uploads: [https://github.com/xob0t/gphotos_mobile_client](https://github.com/xob0t/gphotos_mobile_client)
- Disguise any file as media for GP to accept and store it: [https://github.com/xob0t/gp-file-hide](https://github.com/xob0t/gp-file-hide)

## ♥

If GPTK is useful to you, please consider supporting the project:

BTC `12znTocLytrrYhQT4AJVeJdR8KTULWbKb7`  
BTC Cash `qq7w48d6s3rddgxshl6ae48k7c5jyck76crvppqenn`  
DOGE `DQjBzT2qMuXkLMawUXG7umTf3k9VeT4Y6K`  
Etherium `0xcfe559D9F6056F82a6CFdEDA51c00132035955c8`  
Litecoin `ltc1qcgc873py5k28qm85sk5d53yfwzle4cztmvkh6l`
