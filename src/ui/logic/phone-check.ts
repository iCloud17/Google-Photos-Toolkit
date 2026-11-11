import log from './log';
import { updateUI } from './update-state';
import { core, apiUtils } from '../../globals';
import { parseFingerprintFile, PhoneCheckFileError } from '../../phone-check/fingerprint-file';
import type { FingerprintFile } from '../../phone-check/fingerprint-file';
import { runPhoneCheck } from '../../phone-check/check';
import { countText } from '../../phone-check/count-text';
import type { PhoneCheckResult } from '../../phone-check/check';
import { buildResultFile, RESULT_FILE_NAME } from '../../phone-check/result-file';

const HASHES_PER_REQUEST = 50;
const PARALLEL_ITEM_REQUESTS = 3;

function downloadJsonFile(fileName: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function describeResult(result: PhoneCheckResult): string[] {
  const lines = [
    `Checked ${countText(result.checked, 'fingerprint')}.`,
    `Already in Google Photos: ${result.found.length}`,
    `Not in Google Photos: ${result.notFound}`,
  ];
  if (result.inTrash > 0) lines.push(`In the Google Photos Trash (kept on the phone): ${result.inTrash}`);
  if (result.notInLibrary > 0) lines.push(`Not fully in your library (kept on the phone): ${result.notInLibrary}`);
  if (result.notOriginalQuality > 0) {
    lines.push(`In Google Photos, but not in Original quality (kept on the phone): ${result.notOriginalQuality}`);
  }
  if (result.notChecked > 0) lines.push(`Could not check (kept on the phone): ${result.notChecked}. Run the check again later.`);
  if (!result.complete) lines.push('The check was stopped before the end.');
  lines.push(
    result.found.length > 0
      ? 'Next: tap Download Result. Then run the "clean" command on the phone.'
      : 'Nothing to clean up. Tap Download Result anyway, to replace any older result on the phone.'
  );
  return lines;
}

export default function phoneCheckListenersSetUp(): void {
  const fileInput = document.getElementById('phoneCheckFile') as HTMLInputElement | null;
  const runButton = document.getElementById('phoneCheckRun') as HTMLButtonElement | null;
  const downloadButton = document.getElementById('phoneCheckDownload') as HTMLButtonElement | null;
  const summary = document.getElementById('phoneCheckSummary');
  if (!fileInput || !runButton || !downloadButton || !summary) return;

  let resultFile: string | null = null;

  const showSummary = (lines: string[]): void => {
    summary.replaceChildren(
      ...lines.map((line) => {
        const row = document.createElement('div');
        row.textContent = line;
        return row;
      })
    );
  };

  const runCheck = async (): Promise<void> => {
    if (core.isProcessRunning) {
      log('Phone Check: wait until the running process ends', 'error');
      return;
    }
    const file = fileInput.files?.[0];
    if (!file) {
      showSummary(['First choose the gptk-fingerprints.json file.']);
      return;
    }

    resultFile = null;
    downloadButton.disabled = true;

    let fingerprints: FingerprintFile;
    try {
      fingerprints = parseFingerprintFile(await file.text());
    } catch (error) {
      const message = error instanceof PhoneCheckFileError ? error.message : 'Could not read the file.';
      showSummary([message]);
      log(`Phone Check: ${message}`, 'error');
      return;
    }
    const { hashes, scanId } = fingerprints;
    if (hashes.length === 0) {
      showSummary(['The fingerprint file has no fingerprints. Nothing to check.']);
      return;
    }

    core.isProcessRunning = true;
    runButton.disabled = true;
    updateUI();
    showSummary([`Checking ${countText(hashes.length, 'fingerprint')}...`]);
    log(`Phone Check: checking ${countText(hashes.length, 'fingerprint')}. This changes nothing in Google Photos.`);

    try {
      const api = apiUtils.api;
      const result = await runPhoneCheck(
        hashes,
        {
          getRemoteMatchesByHash: (batch) => api.getRemoteMatchesByHash(batch),
          getTrashItems: (pageId) => api.getTrashItems(pageId),
          getItemInfo: (mediaKey) => api.getItemInfo(mediaKey),
        },
        {
          batchSize: HASHES_PER_REQUEST,
          concurrency: PARALLEL_ITEM_REQUESTS,
          shouldStop: () => !core.isProcessRunning,
          onProgress: (message) => log(`Phone Check: ${message}`),
        }
      );
      showSummary(describeResult(result));
      log(`Phone Check: done. Already in Google Photos: ${result.found.length} of ${result.checked}`, 'success');
      // Always offer the result, also when nothing was found, so it can replace an older result on the phone.
      resultFile = buildResultFile(result, scanId, new Date());
      downloadButton.disabled = false;
    } catch (error) {
      showSummary(['The check failed. Nothing was changed. Try again.']);
      log(`Phone Check: failed: ${error instanceof Error ? error.message : String(error)}`, 'error');
    } finally {
      core.isProcessRunning = false;
      runButton.disabled = false;
      updateUI();
    }
  };

  runButton.addEventListener('click', () => {
    void runCheck();
  });
  downloadButton.addEventListener('click', () => {
    if (resultFile) downloadJsonFile(RESULT_FILE_NAME, resultFile);
  });
}
