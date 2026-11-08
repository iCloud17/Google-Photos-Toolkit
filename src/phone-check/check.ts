import splitArrayIntoChunks from '../utils/splitArrayIntoChunks';
import type { ItemInfo, RemoteMatch, TrashPage } from '../types';
import { countText } from './count-text';

export interface PhoneCheckApi {
  getRemoteMatchesByHash(hashes: string[]): Promise<RemoteMatch[] | null>;
  getTrashItems(pageId: string | null): Promise<TrashPage | null>;
  getItemInfo(mediaKey: string): Promise<ItemInfo | null>;
}

export interface PhoneCheckOptions {
  /** Fingerprints sent in one hash-lookup request. */
  batchSize: number;
  /** Item-info requests that may run at the same time. */
  concurrency: number;
  shouldStop: () => boolean;
  onProgress?: (message: string) => void;
}

export interface FoundItem {
  hash: string;
  mediaKey: string;
}

export interface PhoneCheckResult {
  /** Unique fingerprints that were asked about. */
  checked: number;
  /** Fingerprints of items that are safely in the library (not in Trash, fully uploaded, Original quality). */
  found: FoundItem[];
  notFound: number;
  inTrash: number;
  notInLibrary: number;
  /** Fingerprints whose library item is not confirmed as Original quality (for example, Storage saver). */
  notOriginalQuality: number;
  /** Fingerprints with an unknown state (request failed, or the check was stopped). */
  notChecked: number;
  complete: boolean;
}

type Verdict = { kind: 'found'; mediaKey: string } | { kind: 'inTrash' | 'notInLibrary' | 'notOriginalQuality' | 'notChecked' };

interface TrashKeys {
  mediaKeys: Set<string>;
  dedupKeys: Set<string>;
}

const MAX_TRASH_PAGES = 10000;

async function runPool<T>(items: T[], limit: number, worker: (item: T) => Promise<void>): Promise<void> {
  let nextIndex = 0;
  const workerCount = Math.max(1, Math.min(Math.floor(limit) || 1, items.length));
  const runners = Array.from({ length: workerCount }, async () => {
    while (nextIndex < items.length) {
      const item = items[nextIndex];
      nextIndex += 1;
      await worker(item);
    }
  });
  await Promise.all(runners);
}

/**
 * Reads every Trash page. Throws if any page fails, so a partial Trash list is never trusted.
 * @returns null if the user stopped the process.
 */
async function readWholeTrash(api: PhoneCheckApi, shouldStop: () => boolean): Promise<TrashKeys | null> {
  const keys: TrashKeys = { mediaKeys: new Set(), dedupKeys: new Set() };
  const seenPageIds = new Set<string>();
  let pageId: string | null = null;

  for (let pageCount = 0; pageCount < MAX_TRASH_PAGES; pageCount++) {
    if (shouldStop()) return null;
    const page: TrashPage | null = await api.getTrashItems(pageId);
    for (const item of page?.items ?? []) {
      if (item?.mediaKey) keys.mediaKeys.add(item.mediaKey);
      if (item?.dedupKey) keys.dedupKeys.add(item.dedupKey);
    }
    const nextPageId = page?.nextPageId;
    if (!nextPageId) return keys;
    if (seenPageIds.has(nextPageId)) throw new Error('Trash pages repeat');
    seenPageIds.add(nextPageId);
    pageId = nextPageId;
  }
  throw new Error('Trash has too many pages');
}

/** @returns null if the user stopped the process before all items were asked about. */
async function judgeMatch(
  mediaKeys: string[],
  matchDedupKeys: Map<string, string>,
  api: PhoneCheckApi,
  trash: TrashKeys,
  shouldStop: () => boolean
): Promise<Verdict | null> {
  const seen = new Set<Verdict['kind']>();
  for (const mediaKey of mediaKeys) {
    if (shouldStop()) return null;
    let info: ItemInfo | null;
    try {
      info = await api.getItemInfo(mediaKey);
    } catch {
      seen.add('notChecked');
      continue;
    }
    // Only trust an answer that is about the item we asked for.
    if (info?.mediaKey !== mediaKey) {
      seen.add('notChecked');
      continue;
    }
    const dedupKeys = [info.dedupKey, matchDedupKeys.get(mediaKey)].filter((key): key is string => typeof key === 'string' && key !== '');
    const inTrash =
      trash.mediaKeys.has(mediaKey) ||
      dedupKeys.some((key) => trash.dedupKeys.has(key)) ||
      (info.trashTimestamp !== undefined && info.trashTimestamp !== null);
    if (inTrash) {
      seen.add('inTrash');
      continue;
    }
    if (info.savedToYourPhotos !== true || info.isPartialUpload === true) {
      seen.add('notInLibrary');
      continue;
    }
    // A Storage saver copy is smaller than the phone file, so it is not a full backup.
    if (info.isOriginalQuality !== true) {
      seen.add('notOriginalQuality');
      continue;
    }
    return { kind: 'found', mediaKey };
  }
  if (seen.has('notChecked')) return { kind: 'notChecked' };
  if (seen.has('notOriginalQuality')) return { kind: 'notOriginalQuality' };
  if (seen.has('inTrash')) return { kind: 'inTrash' };
  return { kind: 'notInLibrary' };
}

/**
 * Finds which phone-file fingerprints are already in this Google Photos account.
 * Read-only: it only asks Google questions, it changes nothing.
 * A fingerprint is "found" only if Google returns an item for it, the item is not in the Trash
 * (checked twice: the whole Trash list and the item itself), the item is fully in the library,
 * and it is stored in Original quality.
 * Every failure or unclear answer counts as "not checked", never as "found".
 */
export async function runPhoneCheck(
  hashes: string[],
  api: PhoneCheckApi,
  options: PhoneCheckOptions
): Promise<PhoneCheckResult> {
  const progress = options.onProgress ?? ((): void => undefined);
  const uniqueHashes = [...new Set(hashes)];
  const candidates = new Map<string, string[]>();
  const matchDedupKeys = new Map<string, string>();
  const notChecked = new Set<string>();
  let stopped = false;

  // Step 1: ask Google which fingerprints it has.
  let asked = 0;
  for (const batch of splitArrayIntoChunks(uniqueHashes, options.batchSize)) {
    if (options.shouldStop()) {
      stopped = true;
      batch.forEach((hash) => notChecked.add(hash));
      continue;
    }
    let matches: unknown;
    try {
      matches = await api.getRemoteMatchesByHash(batch);
    } catch {
      matches = undefined;
    }
    // null means "none of these"; anything else that is not a list means the request failed.
    if (matches !== null && !Array.isArray(matches)) {
      batch.forEach((hash) => notChecked.add(hash));
      progress(`Could not check ${countText(batch.length, 'fingerprint')}`);
      continue;
    }
    const batchHashes = new Set(batch);
    for (const match of (matches ?? []) as RemoteMatch[]) {
      if (typeof match?.hash !== 'string' || !batchHashes.has(match.hash)) continue;
      if (typeof match.mediaKey !== 'string' || match.mediaKey === '') continue;
      const keys = candidates.get(match.hash) ?? [];
      if (!keys.includes(match.mediaKey)) keys.push(match.mediaKey);
      candidates.set(match.hash, keys);
      if (typeof match.dedupKey === 'string' && match.dedupKey !== '') matchDedupKeys.set(match.mediaKey, match.dedupKey);
    }
    asked += batch.length;
    progress(`Asked about ${asked} of ${countText(uniqueHashes.length, 'fingerprint')}, matches so far: ${candidates.size}`);
  }

  // Steps 2 and 3: make sure each match is a real library item that is not in the Trash.
  const verdicts = new Map<string, Verdict>();
  const candidateHashes = [...candidates.keys()];
  if (candidateHashes.length > 0 && !stopped) {
    let trash: TrashKeys | null = null;
    try {
      progress('Reading the Google Photos Trash');
      trash = await readWholeTrash(api, options.shouldStop);
      if (trash === null) stopped = true;
    } catch {
      progress('Could not read the Trash, so no match can be confirmed');
    }

    if (trash !== null) {
      const trashKeys = trash;
      let judged = 0;
      progress(`Confirming ${countText(candidateHashes.length, 'match', 'matches')}`);
      await runPool(candidateHashes, options.concurrency, async (hash) => {
        const verdict = await judgeMatch(candidates.get(hash) ?? [], matchDedupKeys, api, trashKeys, options.shouldStop);
        if (verdict === null) {
          stopped = true;
          return;
        }
        verdicts.set(hash, verdict);
        judged += 1;
        if (judged % 50 === 0) progress(`Confirmed ${judged} of ${candidateHashes.length} matches`);
      });
    }
  }

  const result: PhoneCheckResult = {
    checked: uniqueHashes.length,
    found: [],
    notFound: 0,
    inTrash: 0,
    notInLibrary: 0,
    notOriginalQuality: 0,
    notChecked: notChecked.size,
    complete: !stopped,
  };
  for (const hash of uniqueHashes) {
    if (notChecked.has(hash)) continue;
    if (!candidates.has(hash)) {
      result.notFound += 1;
      continue;
    }
    const verdict = verdicts.get(hash) ?? { kind: 'notChecked' };
    if (verdict.kind === 'found') {
      result.found.push({ hash, mediaKey: verdict.mediaKey });
    } else {
      result[verdict.kind] += 1;
    }
  }
  return result;
}
