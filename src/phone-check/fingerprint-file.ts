// Shared by the GPTK "Phone Check" section and tools/phone-check/gptk_phone_check.py.
export const PHONE_CHECK_FORMAT = 'gptk-phone-check';
export const PHONE_CHECK_VERSION = 1;

// A SHA-1 digest is 20 bytes: 26 full base64 characters, then one character that
// holds the last 4 bits (so its 2 low bits are zero), then one '=' pad.
const SHA1_BASE64 = /^[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]=$/;
// Random ID of one scan. The result file repeats it, so the phone script can refuse a result of an older scan.
const SCAN_ID = /^[0-9a-f]{32}$/;

export interface FingerprintFile {
  /** The unique fingerprints (base64 SHA-1 of each phone file). */
  hashes: string[];
  scanId: string;
}

export class PhoneCheckFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PhoneCheckFileError';
  }
}

export function isFingerprint(value: unknown): value is string {
  return typeof value === 'string' && SHA1_BASE64.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Reads the fingerprint file made by the phone script ("scan").
 * @throws PhoneCheckFileError when the file is not a valid fingerprint file.
 */
export function parseFingerprintFile(text: string): FingerprintFile {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new PhoneCheckFileError('This is not a fingerprint file. Choose gptk-fingerprints.json.');
  }

  if (!isRecord(data) || data.format !== PHONE_CHECK_FORMAT || data.type !== 'fingerprints') {
    throw new PhoneCheckFileError('This is not a fingerprint file. Choose gptk-fingerprints.json.');
  }
  if (data.version !== PHONE_CHECK_VERSION) {
    throw new PhoneCheckFileError('This fingerprint file is from a different version of the phone script. Update the script and scan again.');
  }
  if (!Array.isArray(data.hashes) || typeof data.scanId !== 'string' || !SCAN_ID.test(data.scanId)) {
    throw new PhoneCheckFileError('The fingerprint file is damaged. Scan again.');
  }

  const unique = new Set<string>();
  for (const hash of data.hashes) {
    if (!isFingerprint(hash)) {
      throw new PhoneCheckFileError('The fingerprint file is damaged. Scan again.');
    }
    unique.add(hash);
  }
  return { hashes: [...unique], scanId: data.scanId };
}
