import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseFingerprintFile } from '../src/phone-check/fingerprint-file';
import { runPhoneCheck } from '../src/phone-check/check';
import type { PhoneCheckApi } from '../src/phone-check/check';
import { buildResultFile, RESULT_FILE_NAME } from '../src/phone-check/result-file';

// The phone half (Python) and the GPTK half (TypeScript) must agree on the files between them.

const SCRIPT = fileURLToPath(new URL('../tools/phone-check/gptk_phone_check.py', import.meta.url));
const PYTHON = ['python3', 'python'].find((command) => spawnSync(command, ['--version']).status === 0);

interface GoogleItem {
  mediaKey: string;
  trashed?: boolean;
  partial?: boolean;
  storageSaver?: boolean;
}

function sha1(text: string): string {
  return createHash('sha1').update(text).digest('base64');
}

/** A pretend Google Photos account with the given items, keyed by fingerprint. */
function fakeGoogle(items: Map<string, GoogleItem>): PhoneCheckApi {
  const byKey = new Map([...items.values()].map((item) => [item.mediaKey, item]));
  return {
    getRemoteMatchesByHash: (hashes) => {
      const matches = hashes.filter((hash) => items.has(hash)).map((hash) => ({ hash, mediaKey: items.get(hash)?.mediaKey }));
      return Promise.resolve(matches.length > 0 ? matches : null);
    },
    getTrashItems: () =>
      Promise.resolve({
        items: [...items.values()].filter((item) => item.trashed).map((item) => ({ mediaKey: item.mediaKey, dedupKey: `d-${item.mediaKey}`, timestamp: 0, creationTimestamp: 0 })),
      }),
    getItemInfo: (mediaKey) => {
      const item = byKey.get(mediaKey);
      return Promise.resolve(
        item
          ? { mediaKey, dedupKey: `d-${mediaKey}`, savedToYourPhotos: true, isPartialUpload: item.partial === true, isOriginalQuality: item.storageSaver !== true }
          : null
      );
    },
  };
}

describe.skipIf(!PYTHON)('phone script and GPTK Phone Check together', () => {
  let storage: string;
  let files: Record<'backedUp' | 'backedUpCopy' | 'trashed' | 'partial' | 'storageSaver' | 'phoneOnly', string>;

  const put = (relativePath: string, content: string): string => {
    const path = join(storage, 'Android/media/com.whatsapp/WhatsApp/Media', relativePath);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    return path;
  };
  const runScript = (args: string[], answer = ''): number | null =>
    spawnSync(PYTHON ?? 'python3', [SCRIPT, ...args, '--storage', storage], { input: answer, encoding: 'utf8' }).status;

  /** Runs scan on the phone, then the GPTK check against a pretend account, and saves the result in Download. */
  const scanAndCheck = async (): Promise<void> => {
    expect(runScript(['scan']), 'scan succeeds').toBe(0);
    const { hashes, scanId } = parseFingerprintFile(readFileSync(join(storage, 'Download', 'gptk-fingerprints.json'), 'utf8'));
    const google = new Map<string, GoogleItem>([
      [sha1('backed up photo'), { mediaKey: 'AF1QipBackedUp' }],
      [sha1('photo in the Trash'), { mediaKey: 'AF1QipTrashed', trashed: true }],
      [sha1('partly uploaded video'), { mediaKey: 'AF1QipPartial', partial: true }],
      [sha1('storage saver photo'), { mediaKey: 'AF1QipSaver', storageSaver: true }],
    ]);
    const result = await runPhoneCheck(hashes, fakeGoogle(google), { batchSize: 2, concurrency: 2, shouldStop: () => false });
    writeFileSync(join(storage, 'Download', RESULT_FILE_NAME), buildResultFile(result, scanId, new Date()));
  };

  beforeEach(() => {
    storage = mkdtempSync(join(tmpdir(), 'gptk-phone-'));
    mkdirSync(join(storage, 'Download'));
    files = {
      backedUp: put('WhatsApp Images/IMG-1.jpg', 'backed up photo'),
      backedUpCopy: put('WhatsApp Images/Sent/IMG-1.jpg', 'backed up photo'),
      trashed: put('WhatsApp Images/IMG-2.jpg', 'photo in the Trash'),
      partial: put('WhatsApp Video/VID-1.mp4', 'partly uploaded video'),
      storageSaver: put('WhatsApp Images/IMG-4.jpg', 'storage saver photo'),
      phoneOnly: put('WhatsApp Images/IMG-3.jpg', 'photo only on the phone'),
    };
  });

  afterEach(() => {
    rmSync(storage, { recursive: true, force: true });
  });

  // The phone deletes exactly the files that GPTK confirmed, and keeps all the others.
  it('deletes on the phone only the files that GPTK confirmed', async () => {
    await scanAndCheck();

    expect(runScript(['clean'], 'yes\n'), 'clean succeeds').toBe(0);

    expect(existsSync(files.backedUp), 'the backed-up photo is deleted').toBe(false);
    expect(existsSync(files.backedUpCopy), 'its copy in Sent is deleted').toBe(false);
    expect(existsSync(files.trashed), 'a photo whose Google copy is in the Trash is kept').toBe(true);
    expect(existsSync(files.partial), 'a partly uploaded video is kept').toBe(true);
    expect(existsSync(files.storageSaver), 'a photo that Google keeps only in Storage saver quality is kept').toBe(true);
    expect(existsSync(files.phoneOnly), 'a photo that is not in Google Photos is kept').toBe(true);
  });

  // A result of an earlier scan is refused after a new scan, so an outdated check can never delete files.
  it('refuses a result that was made for an earlier scan', async () => {
    await scanAndCheck();
    expect(runScript(['scan']), 'the second scan succeeds').toBe(0);

    expect(runScript(['clean'], 'yes\n'), 'clean refuses the result of the earlier scan').toBe(2);

    expect(Object.values(files).every((path) => existsSync(path)), 'every file is still on the phone').toBe(true);
  });

  // Typing anything other than yes at the real prompt keeps every file.
  it('keeps every file when the answer at the prompt is not yes', async () => {
    await scanAndCheck();

    expect(runScript(['clean'], 'no\n'), 'clean reports that it was cancelled').toBe(1);

    expect(Object.values(files).every((path) => existsSync(path)), 'every file is still on the phone').toBe(true);
  });
});
