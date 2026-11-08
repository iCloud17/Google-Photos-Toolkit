import { PHONE_CHECK_FORMAT, PHONE_CHECK_VERSION } from './fingerprint-file';
import type { PhoneCheckResult } from './check';

export const RESULT_FILE_NAME = 'gptk-result.json';

/**
 * Makes the result file for the phone script ("clean").
 * Only "found" fingerprints are listed, so the phone script can never delete a file
 * whose state in Google Photos is unknown.
 * @param scanId The scan ID from the fingerprint file that was checked.
 */
export function buildResultFile(result: PhoneCheckResult, scanId: string, createdAt: Date): string {
  const content = {
    format: PHONE_CHECK_FORMAT,
    type: 'result',
    version: PHONE_CHECK_VERSION,
    created: createdAt.toISOString(),
    scanId,
    complete: result.complete,
    counts: {
      checked: result.checked,
      found: result.found.length,
      notFound: result.notFound,
      inTrash: result.inTrash,
      notInLibrary: result.notInLibrary,
      notOriginalQuality: result.notOriginalQuality,
      notChecked: result.notChecked,
    },
    found: result.found.map(({ hash, mediaKey }) => ({ hash, mediaKey })),
  };
  return JSON.stringify(content, null, 2);
}
