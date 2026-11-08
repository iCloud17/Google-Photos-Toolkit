import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import parser from '../src/api/parser';
import { runPhoneCheck } from '../src/phone-check/check';
import type { PhoneCheckApi, PhoneCheckOptions, PhoneCheckResult } from '../src/phone-check/check';
import { parseFingerprintFile, isFingerprint, PhoneCheckFileError } from '../src/phone-check/fingerprint-file';
import { buildResultFile } from '../src/phone-check/result-file';
import type { ItemInfo, RemoteMatch, TrashPage } from '../src/types';
import swbisb from './fixtures/parser/swbisb.json';
import VrseUb from './fixtures/parser/VrseUb.json';

// ── Helpers ───────────────────────────────────────────────────────────

/** Fingerprint exactly like the phone script: standard base64 of the SHA-1 digest. */
function fingerprint(content: string | Buffer): string {
  return createHash('sha1').update(content).digest('base64');
}

interface FakeItem {
  hash: string;
  mediaKey: string;
  dedupKey?: string;
  trashed?: 'trash-list' | 'trash-list-dedup-only' | 'item-flag';
  saved?: boolean;
  partial?: boolean;
  originalQuality?: boolean | null;
}

interface FakeApiOptions {
  failLookupFor?: string[];
  malformedLookupFor?: string[];
  /** Matches added to answers for requests that did not ask about them. */
  strayMatches?: RemoteMatch[];
  failTrash?: boolean;
  trashPageSize?: number;
  repeatTrashPages?: boolean;
  failInfoFor?: string[];
  wrongInfoFor?: string[];
  infoOverride?: Record<string, ItemInfo>;
}

/** A pretend Google Photos account that answers like the GPTK Api class. */
function makeFakeApi(items: FakeItem[], options: FakeApiOptions = {}) {
  const lookupCalls: string[][] = [];
  const infoCalls: string[] = [];
  const trashCalls: (string | null)[] = [];
  const dedupOf = (item: FakeItem): string => item.dedupKey ?? `dedup-${item.mediaKey}`;

  const api: PhoneCheckApi = {
    getRemoteMatchesByHash(hashes) {
      lookupCalls.push([...hashes]);
      if (hashes.some((hash) => options.failLookupFor?.includes(hash))) {
        return Promise.reject(new Error('lookup failed'));
      }
      if (hashes.some((hash) => options.malformedLookupFor?.includes(hash))) {
        return Promise.resolve({} as unknown as RemoteMatch[]);
      }
      const matches: RemoteMatch[] = items
        .filter((item) => hashes.includes(item.hash))
        .map((item) => ({ hash: item.hash, mediaKey: item.mediaKey, dedupKey: dedupOf(item) }));
      const stray = (options.strayMatches ?? []).filter((match) => !hashes.includes(match.hash ?? ''));
      const all = [...matches, ...stray];
      // The real parser returns null for an empty answer.
      return Promise.resolve(all.length > 0 ? all : null);
    },

    getTrashItems(pageId) {
      trashCalls.push(pageId);
      if (options.failTrash) return Promise.reject(new Error('trash failed'));
      const trashed = items
        .filter((item) => item.trashed === 'trash-list' || item.trashed === 'trash-list-dedup-only')
        .map((item) => ({
          mediaKey: item.trashed === 'trash-list' ? item.mediaKey : `trash-copy-${item.mediaKey}`,
          dedupKey: dedupOf(item),
          timestamp: 0,
          creationTimestamp: 0,
        }));
      const pageSize = options.trashPageSize ?? 1000;
      const pageNumber = pageId === null ? 0 : Number(pageId.replace('page-', ''));
      const page: TrashPage = { items: trashed.slice(pageNumber * pageSize, (pageNumber + 1) * pageSize) };
      if (options.repeatTrashPages) page.nextPageId = 'page-1';
      else if ((pageNumber + 1) * pageSize < trashed.length) page.nextPageId = `page-${pageNumber + 1}`;
      return Promise.resolve(page);
    },

    getItemInfo(mediaKey) {
      infoCalls.push(mediaKey);
      if (options.failInfoFor?.includes(mediaKey)) return Promise.reject(new Error('info failed'));
      if (options.infoOverride?.[mediaKey]) return Promise.resolve(options.infoOverride[mediaKey]);
      const item = items.find((candidate) => candidate.mediaKey === mediaKey);
      if (!item) return Promise.resolve(null);
      if (options.wrongInfoFor?.includes(mediaKey)) {
        return Promise.resolve({ mediaKey: 'some-other-item', savedToYourPhotos: true, isPartialUpload: false });
      }
      return Promise.resolve({
        mediaKey,
        dedupKey: dedupOf(item),
        trashTimestamp: item.trashed === 'item-flag' ? 1700000000000 : undefined,
        savedToYourPhotos: item.saved ?? true,
        isPartialUpload: item.partial ?? false,
        isOriginalQuality: item.originalQuality === undefined ? true : item.originalQuality,
      });
    },
  };
  return { api, lookupCalls, infoCalls, trashCalls };
}

/** A Google answer for a normal item in the library. */
function libraryItem(mediaKey: string): ItemInfo {
  return { mediaKey, savedToYourPhotos: true, isPartialUpload: false, isOriginalQuality: true };
}

function options(overrides: Partial<PhoneCheckOptions> = {}): PhoneCheckOptions {
  return { batchSize: 50, concurrency: 3, shouldStop: () => false, ...overrides };
}

function total(result: PhoneCheckResult): number {
  return result.found.length + result.notFound + result.inTrash + result.notInLibrary + result.notOriginalQuality + result.notChecked;
}

const hashA = fingerprint('photo A');
const hashB = fingerprint('photo B');
const hashC = fingerprint('photo C');
const hashD = fingerprint('photo D');
const hashE = fingerprint('photo E');
const scanId = '0123456789abcdef0123456789abcdef';

// ── runPhoneCheck ─────────────────────────────────────────────────────

describe('runPhoneCheck', () => {
  // A file counts as "found" only when Google has it in the library; other files stay "not found".
  it('reports only the files that are in the Google Photos library', async () => {
    const { api } = makeFakeApi([{ hash: hashA, mediaKey: 'item-a' }]);

    const result = await runPhoneCheck([hashA, hashB], api, options());

    expect(result.found, 'only photo A is in Google Photos').toEqual([{ hash: hashA, mediaKey: 'item-a' }]);
    expect(result.notFound, 'photo B is unknown to Google').toBe(1);
    expect(result.complete, 'nothing interrupted the check').toBe(true);
  });

  // A Storage saver copy (or a copy of unknown quality) is smaller than the phone file, so the phone file is kept.
  it('keeps files whose Google copy is not in Original quality', async () => {
    const { api } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a', originalQuality: false },
      { hash: hashB, mediaKey: 'item-b', originalQuality: null },
    ]);

    const result = await runPhoneCheck([hashA, hashB], api, options());

    expect(result.found, 'a lower-quality copy is not a full backup').toEqual([]);
    expect(result.notOriginalQuality, 'both files are reported as not in Original quality').toBe(2);
  });

  // An item that is in the Trash will disappear, so its phone file must be kept.
  it('keeps files whose Google copy is in the Trash list', async () => {
    const { api } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a', trashed: 'trash-list' },
      { hash: hashB, mediaKey: 'item-b', trashed: 'trash-list-dedup-only' },
    ]);

    const result = await runPhoneCheck([hashA, hashB], api, options());

    expect(result.found, 'trashed items must never be offered for deletion').toEqual([]);
    expect(result.inTrash, 'both trashed items are reported as in the Trash').toBe(2);
  });

  // The item itself can also say that it is in the Trash.
  it('keeps files whose Google copy is marked as trashed', async () => {
    const { api } = makeFakeApi([{ hash: hashA, mediaKey: 'item-a', trashed: 'item-flag' }]);

    const result = await runPhoneCheck([hashA], api, options());

    expect(result.found, 'an item flagged as trashed is not a safe backup').toEqual([]);
    expect(result.inTrash, 'the flagged item is reported as in the Trash').toBe(1);
  });

  // A Trash item on a later page must still be seen.
  it('reads every Trash page before deciding', async () => {
    const { api } = makeFakeApi(
      [
        { hash: hashA, mediaKey: 'item-a', trashed: 'trash-list' },
        { hash: hashB, mediaKey: 'item-b', trashed: 'trash-list' },
        { hash: hashC, mediaKey: 'item-c', trashed: 'trash-list' },
      ],
      { trashPageSize: 1 }
    );

    const result = await runPhoneCheck([hashA, hashB, hashC], api, options());

    expect(result.found, 'items on any Trash page are not safe backups').toEqual([]);
    expect(result.inTrash, 'all three trashed items are recognised').toBe(3);
  });

  // Items that are not fully in the user's own library are not a safe backup.
  it('keeps files whose Google copy is not saved in the library or only partly uploaded', async () => {
    const { api } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a', saved: false },
      { hash: hashB, mediaKey: 'item-b', partial: true },
    ]);

    const result = await runPhoneCheck([hashA, hashB], api, options());

    expect(result.found, 'unsaved and partial items are not safe backups').toEqual([]);
    expect(result.notInLibrary, 'both items are reported as not in the library').toBe(2);
  });

  // When the Trash cannot be read, no match can be proven safe.
  it('confirms nothing when the Trash cannot be read', async () => {
    const { api } = makeFakeApi([{ hash: hashA, mediaKey: 'item-a' }], { failTrash: true });

    const result = await runPhoneCheck([hashA, hashB], api, options());

    expect(result.found, 'without the Trash list nothing may be offered for deletion').toEqual([]);
    expect(result.notChecked, 'the unconfirmed match is reported as not checked').toBe(1);
    expect(result.notFound, 'the file Google does not have is still reported').toBe(1);
  });

  // Endless Trash paging must not be treated as a complete Trash list.
  it('confirms nothing when Trash pages repeat', async () => {
    const { api } = makeFakeApi([{ hash: hashA, mediaKey: 'item-a' }], { repeatTrashPages: true });

    const result = await runPhoneCheck([hashA], api, options());

    expect(result.found, 'a broken Trash list must not confirm anything').toEqual([]);
    expect(result.notChecked, 'the match is reported as not checked').toBe(1);
  });

  // A failed lookup must not look like "not in Google Photos", and other batches must still run.
  it('marks a failed lookup as not checked and still checks the other batches', async () => {
    const { api } = makeFakeApi([{ hash: hashC, mediaKey: 'item-c' }], { failLookupFor: [hashA] });

    const result = await runPhoneCheck([hashA, hashB, hashC], api, options({ batchSize: 2 }));

    expect(result.notChecked, 'both fingerprints in the failed batch are not checked').toBe(2);
    expect(result.found.map((item) => item.hash), 'the second batch is still checked').toEqual([hashC]);
  });

  // An answer that is not a list is a failure, not "nothing found".
  it('marks a malformed lookup answer as not checked', async () => {
    const { api } = makeFakeApi([{ hash: hashA, mediaKey: 'item-a' }], { malformedLookupFor: [hashA] });

    const result = await runPhoneCheck([hashA], api, options());

    expect(result.notChecked, 'a malformed answer gives no information').toBe(1);
    expect(result.found, 'nothing is confirmed from a malformed answer').toEqual([]);
  });

  // Item answers that fail or describe another item cannot confirm anything.
  it('marks failed or mismatched item answers as not checked', async () => {
    const { api } = makeFakeApi(
      [
        { hash: hashA, mediaKey: 'item-a' },
        { hash: hashB, mediaKey: 'item-b' },
        { hash: hashC, mediaKey: 'item-c' },
      ],
      { failInfoFor: ['item-a'], wrongInfoFor: ['item-b'] }
    );

    const result = await runPhoneCheck([hashA, hashB, hashC], api, options());

    expect(result.notChecked, 'failed and mismatched answers are not checked').toBe(2);
    expect(result.found.map((item) => item.hash), 'the healthy item is still confirmed').toEqual([hashC]);
  });

  // An answer is trusted only for the fingerprints that its request asked about.
  it('ignores matches for fingerprints that the request did not ask about', async () => {
    const { api } = makeFakeApi([], {
      strayMatches: [
        { hash: hashB, mediaKey: 'item-b' },
        { hash: hashD, mediaKey: 'item-d' },
      ],
      infoOverride: { 'item-b': libraryItem('item-b'), 'item-d': libraryItem('item-d') },
    });

    const result = await runPhoneCheck([hashA, hashB], api, options({ batchSize: 1 }));

    expect(result.found, 'a match from the answer to another request must not be trusted').toEqual([]);
    expect(result.notFound, 'Google did not report either requested fingerprint').toBe(2);
  });

  // One fingerprint can belong to several Google items; one safe item is enough.
  it('confirms a fingerprint when any of its Google items is safe', async () => {
    const { api } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a-trashed', trashed: 'trash-list' },
      { hash: hashA, mediaKey: 'item-a-kept' },
    ]);

    const result = await runPhoneCheck([hashA], api, options());

    expect(result.found, 'the safe copy confirms the backup').toEqual([{ hash: hashA, mediaKey: 'item-a-kept' }]);
  });

  // Requests stay small, every fingerprint is asked about once, and repeats are removed.
  it('asks about each fingerprint once in batches no larger than the batch size', async () => {
    const hashes = Array.from({ length: 7 }, (_, index) => fingerprint(`file ${index}`));
    const { api, lookupCalls } = makeFakeApi([]);

    const result = await runPhoneCheck([...hashes, hashes[0], hashes[3]], api, options({ batchSize: 3 }));

    expect(lookupCalls.every((call) => call.length <= 3), 'no request is larger than the batch size').toBe(true);
    expect(lookupCalls.flat().sort(), 'every fingerprint is asked about exactly once').toEqual([...hashes].sort());
    expect(result.checked, 'repeated fingerprints are counted once').toBe(7);
  });

  // Pressing Stop ends the check, and unfinished work is never reported as safe.
  it('stops when asked and reports unfinished work as not checked', async () => {
    const { api } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a' },
      { hash: hashC, mediaKey: 'item-c' },
    ]);
    let lookups = 0;
    const countingApi: PhoneCheckApi = {
      ...api,
      getRemoteMatchesByHash: (hashes) => {
        lookups += 1;
        return api.getRemoteMatchesByHash(hashes);
      },
    };

    const result = await runPhoneCheck([hashA, hashB, hashC, hashD], countingApi, options({ batchSize: 2, shouldStop: () => lookups >= 1 }));

    expect(lookups, 'no more fingerprints are sent to Google after Stop').toBe(1);
    expect(result.complete, 'the result says that the check was stopped').toBe(false);
    expect(result.found, 'nothing is confirmed after a stop').toEqual([]);
    expect(total(result), 'every fingerprint is still accounted for').toBe(4);
  });

  // Stop also works while matches are being confirmed; finished answers are kept, the rest is not checked.
  it('stops while confirming matches and keeps the unconfirmed ones on the phone', async () => {
    const { api, infoCalls } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a' },
      { hash: hashB, mediaKey: 'item-b' },
      { hash: hashC, mediaKey: 'item-c' },
    ]);

    const result = await runPhoneCheck([hashA, hashB, hashC], api, options({ concurrency: 1, shouldStop: () => infoCalls.length >= 1 }));

    expect(infoCalls.length, 'no more items are looked up after Stop').toBe(1);
    expect(result.complete, 'the result says that the check was stopped').toBe(false);
    expect(result.found.length, 'only the fully checked match is confirmed').toBe(1);
    expect(result.notChecked, 'the matches not yet confirmed are not checked').toBe(2);
  });

  // Stop also works between the Google items of one fingerprint; that fingerprint is then not checked.
  it('stops between the Google items of one fingerprint', async () => {
    const { api, infoCalls } = makeFakeApi([
      { hash: hashA, mediaKey: 'item-a-trashed', trashed: 'trash-list' },
      { hash: hashA, mediaKey: 'item-a-second' },
      { hash: hashA, mediaKey: 'item-a-third' },
    ]);

    const result = await runPhoneCheck([hashA], api, options({ shouldStop: () => infoCalls.length >= 1 }));

    expect(infoCalls, 'no more items are looked up after Stop').toEqual(['item-a-trashed']);
    expect(result.complete, 'the result says that the check was stopped').toBe(false);
    expect(result.notChecked, 'the fingerprint with unchecked items is not checked').toBe(1);
  });

  // Stop also works while a large Trash is being read, and nothing is confirmed then.
  it('stops while reading the Trash', async () => {
    const { api, trashCalls } = makeFakeApi(
      [
        { hash: hashA, mediaKey: 'item-a' },
        { hash: hashB, mediaKey: 'item-b', trashed: 'trash-list' },
        { hash: hashC, mediaKey: 'item-c', trashed: 'trash-list' },
        { hash: hashD, mediaKey: 'item-d', trashed: 'trash-list' },
      ],
      { trashPageSize: 1 }
    );

    const result = await runPhoneCheck([hashA, hashB, hashC, hashD], api, options({ shouldStop: () => trashCalls.length >= 1 }));

    expect(trashCalls.length, 'no more Trash pages are read after Stop').toBe(1);
    expect(result.complete, 'the result says that the check was stopped').toBe(false);
    expect(result.found, 'nothing is confirmed without the whole Trash list').toEqual([]);
  });

  // The counts always add up, so the summary never hides a file.
  it('puts every fingerprint in exactly one group', async () => {
    const { api } = makeFakeApi(
      [
        { hash: hashA, mediaKey: 'item-a' },
        { hash: hashB, mediaKey: 'item-b', trashed: 'trash-list' },
        { hash: hashC, mediaKey: 'item-c', saved: false },
        { hash: hashE, mediaKey: 'item-e', originalQuality: false },
      ],
      { failLookupFor: [hashD] }
    );

    const result = await runPhoneCheck([hashA, hashB, hashC, hashD, hashE, fingerprint('photo F')], api, options({ batchSize: 5 }));

    expect(total(result), 'the groups add up to the number of fingerprints').toBe(result.checked);
    expect(result.checked, 'six different fingerprints were given').toBe(6);
  });

  // A real library item answer from Google (recorded fixture) passes the safety checks.
  it('confirms a match when Google answers with a normal library item', async () => {
    const realInfo = parser(VrseUb, 'VrseUb') as ItemInfo;
    const realMatch = (parser(swbisb, 'swbisb') as RemoteMatch[])[0];
    const mediaKey = realInfo.mediaKey ?? '';
    const { api } = makeFakeApi([{ hash: realMatch.hash ?? '', mediaKey }], { infoOverride: { [mediaKey]: realInfo } });

    const result = await runPhoneCheck([realMatch.hash ?? ''], api, options());

    expect(result.found.map((item) => item.mediaKey), 'a real library item is a safe backup').toEqual([mediaKey]);
  });
});

// ── Fingerprint file ──────────────────────────────────────────────────

describe('parseFingerprintFile', () => {
  const validContent = (hashes: unknown[]) => ({ format: 'gptk-phone-check', type: 'fingerprints', version: 1, created: '2026-01-01T00:00:00Z', scanId, hashes });
  const validFile = (hashes: unknown[]) => JSON.stringify(validContent(hashes));

  // The file from the phone script is read, and repeated fingerprints are dropped.
  it('reads the fingerprints from the phone script and drops repeats', () => {
    const { hashes } = parseFingerprintFile(validFile([hashA, hashB, hashA]));

    expect(hashes.sort(), 'each fingerprint appears once').toEqual([hashA, hashB].sort());
  });

  // Files that are not fingerprint files are refused with a clear error type.
  it.each([
    ['text that is not JSON', 'hello'],
    ['a JSON list', '[]'],
    ['a file of another tool', JSON.stringify({ hashes: [hashA] })],
    ['a GPTK result file', JSON.stringify({ format: 'gptk-phone-check', type: 'result', version: 1, scanId, found: [] })],
    ['a file from another version', JSON.stringify({ ...validContent([hashA]), version: 2 })],
    ['a file without a fingerprint list', JSON.stringify({ ...validContent([]), hashes: undefined })],
    ['a file without a scan ID', JSON.stringify({ ...validContent([hashA]), scanId: undefined })],
    ['a file with a damaged scan ID', JSON.stringify({ ...validContent([hashA]), scanId: '../0123456789abcdef0123456789ab' })],
  ])('refuses %s', (_label, text) => {
    expect(() => parseFingerprintFile(text), 'only fingerprint files are accepted').toThrow(PhoneCheckFileError);
  });

  // One damaged fingerprint makes the whole file untrustworthy.
  it.each([
    ['a hex SHA-1', createHash('sha1').update('x').digest('hex')],
    ['a too short value', hashA.slice(1)],
    ['a value without padding', hashA.replace('=', '')],
    ['a value with impossible last bits', `${hashA.slice(0, 26)}B=`],
    ['a URL-safe value', `${'-'.repeat(26)}A=`],
    ['a number', 42],
  ])('refuses a file with %s', (_label, badHash) => {
    expect(() => parseFingerprintFile(validFile([hashA, badHash])), 'damaged fingerprints are refused').toThrow(PhoneCheckFileError);
  });

  // Every real SHA-1 digest is accepted, whatever its bytes are.
  it('accepts real SHA-1 fingerprints', () => {
    const samples = Array.from({ length: 200 }, () => fingerprint(randomBytes(32)));

    expect(samples.every(isFingerprint), 'all real fingerprints are valid').toBe(true);
  });

  // The fingerprints Google sends back use the same format as the phone script.
  it('uses the same fingerprint format as Google', () => {
    const googleHashes = (parser(swbisb, 'swbisb') as RemoteMatch[]).map((match) => match.hash);

    expect(googleHashes.every(isFingerprint), 'Google fingerprints match the phone fingerprint format').toBe(true);
  });
});

// ── Result file ───────────────────────────────────────────────────────

describe('buildResultFile', () => {
  const result: PhoneCheckResult = {
    checked: 6,
    found: [{ hash: hashA, mediaKey: 'item-a' }],
    notFound: 2,
    inTrash: 1,
    notInLibrary: 0,
    notOriginalQuality: 1,
    notChecked: 1,
    complete: true,
  };

  // The phone script needs the format marker and the found fingerprints only.
  it('lists only the found fingerprints under the phone-check format', () => {
    const file = JSON.parse(buildResultFile(result, scanId, new Date('2026-01-02T03:04:05Z'))) as Record<string, unknown>;

    expect(file.format, 'the phone script recognises the file').toBe('gptk-phone-check');
    expect(file.type, 'the file is a result, not a fingerprint list').toBe('result');
    expect(file.version, 'the phone script knows this version').toBe(1);
    expect(file.found, 'only the confirmed item is listed').toEqual([{ hash: hashA, mediaKey: 'item-a' }]);
  });

  // The result names the scan that it checked, so the phone script can refuse a result of an older scan.
  it('carries the scan ID of the checked fingerprint file', () => {
    const fingerprintFile = JSON.stringify({ format: 'gptk-phone-check', type: 'fingerprints', version: 1, scanId, hashes: [hashA] });

    const file = JSON.parse(buildResultFile(result, parseFingerprintFile(fingerprintFile).scanId, new Date())) as Record<string, unknown>;

    expect(file.scanId, 'the result belongs to the scan that made the fingerprint file').toBe(scanId);
  });

  // A stopped check is visible in the file, so the phone script can warn.
  it('records whether the check finished', () => {
    const file = JSON.parse(buildResultFile({ ...result, complete: false }, scanId, new Date())) as Record<string, unknown>;

    expect(file.complete, 'a stopped check is recorded').toBe(false);
  });

  // A result file is never mistaken for a fingerprint file.
  it('cannot be used as a fingerprint file', () => {
    const text = buildResultFile(result, scanId, new Date());

    expect(() => parseFingerprintFile(text), 'result files are not fingerprint files').toThrow(PhoneCheckFileError);
  });
});
