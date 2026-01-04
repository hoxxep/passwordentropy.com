// Password entropy and crack time calculations

import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

// Initialize zxcvbn with English dictionary and common adjacency graphs
zxcvbnOptions.setOptions({
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  translations: zxcvbnEnPackage.translations,
});

// Hash rates per GPU (hashes per second) based on RTX 5090 hashcat benchmarks
//
// Sources:
// - RTX 5090: https://gist.github.com/Chick3nman/09bac0775e6393468c2925c1e1363d5c
// - RTX 4090: https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
// - Argon2id (hashcat 7.0.0): https://hashcat.net/forum/thread-11277.html
//
// KDF rates are scaled to production-realistic parameters:
// - PBKDF2: 310,000 iterations (Django 4.x default for SHA-256)
// - bcrypt: cost 10 (1,024 rounds, common production default)
// - scrypt: N=16384, r=1, p=1 (hashcat benchmark default)
// - Argon2id: m=65536 (64 MiB), t=3, p=1 (RFC 9106 first recommendation)
//
export const hashRates: Record<string, number> = {
  // Fast hashes (RTX 5090, hashcat -b)
  none: 1e12,           // Plain text comparison: ~1 trillion/s (estimated)
  md5: 220.6e9,         // 220.6 GH/s (mode 0)
  sha1: 70.2e9,         // 70.2 GH/s (mode 100)
  sha512: 10e9,         // 10.0 GH/s (mode 1700)

  // KDFs with production parameters (RTX 5090, scaled from benchmarks)
  // Benchmark: 11.2 MH/s @ 999 iterations → scaled to 310k iterations
  pbkdf2: 36e3,         // ~36 kH/s (mode 10900, PBKDF2-HMAC-SHA256, 310k iter)

  // Benchmark: 304.8 kH/s @ cost 5 → scaled to cost 10 (32x slower)
  bcrypt: 9.5e3,        // ~9.5 kH/s (mode 3200, cost 10)

  // Benchmark: 7,760 H/s @ N=16384, r=1, p=1
  scrypt: 7.76e3,       // ~7.8 kH/s (mode 8900, N=16384, r=1, p=1)

  // RTX 4090: 1,703 H/s @ m=65536, t=3, p=1 (hashcat 7.0.0)
  // Estimated ~1.3x for RTX 5090
  argon2id: 2.2e3,      // ~2.2 kH/s (mode 34000, m=64MiB, t=3, p=1)
};

// GPU scale configurations
export interface GPUScale {
  label: string;
  gpuCount: number;
}

export const gpuScales: GPUScale[] = [
  { label: '1 GPU', gpuCount: 1 },
  { label: '10 GPUs', gpuCount: 10 },
  { label: '100 GPUs', gpuCount: 100 },
  { label: '1k GPUs', gpuCount: 1000 },
  { label: '10k GPUs', gpuCount: 10000 },
  { label: 'Nation State', gpuCount: 1000000 },
];

// Hashing algorithms
export interface HashAlgorithm {
  label: string;
  key: string;
}

export const hashAlgorithms: HashAlgorithm[] = [
  { label: 'MD5', key: 'md5' },
  { label: 'SHA-1', key: 'sha1' },
  { label: 'SHA-512', key: 'sha512' },
  { label: 'PBKDF2', key: 'pbkdf2' },
  { label: 'bcrypt', key: 'bcrypt' },
  { label: 'scrypt', key: 'scrypt' },
  { label: 'Argon2id', key: 'argon2id' },
];

// Character set sizes for entropy calculation
const CHARSET_SIZES = {
  lowercase: 26,
  uppercase: 26,
  digits: 10,
  symbols: 32,  // Common symbols: !@#$%^&*()_+-=[]{}|;':",.<>?/`~
  space: 1,
};

/**
 * Analyze a password and determine which character sets it uses.
 */
export function analyzePassword(password: string): {
  hasLowercase: boolean;
  hasUppercase: boolean;
  hasDigits: boolean;
  hasSymbols: boolean;
  hasSpace: boolean;
  charsetSize: number;
  length: number;
} {
  const hasLowercase = /[a-z]/.test(password);
  const hasUppercase = /[A-Z]/.test(password);
  const hasDigits = /[0-9]/.test(password);
  const hasSpace = / /.test(password);
  // Symbols: anything that's not alphanumeric or space
  const hasSymbols = /[^a-zA-Z0-9 ]/.test(password);

  let charsetSize = 0;
  if (hasLowercase) charsetSize += CHARSET_SIZES.lowercase;
  if (hasUppercase) charsetSize += CHARSET_SIZES.uppercase;
  if (hasDigits) charsetSize += CHARSET_SIZES.digits;
  if (hasSymbols) charsetSize += CHARSET_SIZES.symbols;
  if (hasSpace) charsetSize += CHARSET_SIZES.space;

  return {
    hasLowercase,
    hasUppercase,
    hasDigits,
    hasSymbols,
    hasSpace,
    charsetSize,
    length: password.length,
  };
}

/**
 * Calculate password entropy in bits using zxcvbn.
 * Converts guessesLog10 to log2: entropy = guessesLog10 * log2(10)
 */
export function calculateEntropy(password: string): number | undefined {
  if (password.length === 0) return undefined;

  const result = zxcvbn(password);
  // Convert log10(guesses) to log2(guesses) for bits of entropy
  return result.guessesLog10 * Math.log2(10);
}

/**
 * Calculate time to crack in seconds.
 * Time = (2^entropy) / (hashRate * gpuCount)
 * We divide by 2 on average since we expect to find it halfway through the search space.
 */
export function calculateCrackTime(
  entropy: number,
  hashKey: string,
  gpuCount: number
): number {
  if (entropy === 0) return 0;

  const hashRate = hashRates[hashKey] || hashRates.sha512;
  const totalHashesPerSecond = hashRate * gpuCount;

  // Total possible combinations
  const totalCombinations = Math.pow(2, entropy);

  // Average case: we find it after trying half the combinations
  const averageAttempts = totalCombinations / 2;

  return averageAttempts / totalHashesPerSecond;
}

/**
 * Format time duration for display.
 * Uses appropriate units from seconds up to billions of years.
 */
export function formatCrackTime(seconds: number): string {
  if (seconds < 60) return 'Instant';  // < 1 minute

  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} min`;

  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hrs`;

  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;

  const months = days / 30;
  if (months < 12) return `${Math.round(months)} mo`;

  const years = days / 365.25;
  if (years < 1000) return `${Math.round(years)} yrs`;

  if (years < 1e6) return `${(years / 1000).toFixed(0)}k yrs`;
  if (years < 1e9) return `${(years / 1e6).toFixed(0)}M yrs`;
  if (years < 1e12) return `${(years / 1e9).toFixed(0)}B yrs`;
  if (years < 1e15) return `${(years / 1e12).toFixed(0)}T yrs`;

  // Beyond trillions of years
  return '∞';
}

/**
 * Get tier for color coding based on crack time.
 * tier-1 (purple): Instant - under 10 minutes
 * tier-2 (red): Minutes/hours/weeks - 10 min to 1 year
 * tier-3 (orange): Moderate - 1 year to 100k years
 * tier-4 (yellow): Strong - 100k years to 10 billion years
 * tier-5 (green): Very strong - 10+ billion years
 */
export function getCrackTimeTier(seconds: number): string {
  if (seconds < 60 * 60 * 24) return 'tier-1';     // < 1 day (instant)
  if (seconds < 31557600) return 'tier-2';         // < 1 year
  if (seconds < 3.1557e11) return 'tier-3';        // < 1 thousand ears
  if (seconds < 3.1557e16) return 'tier-4';        // < 1 billion years
  return 'tier-5';                                 // >= 1 billion years
}

/**
 * Result of getCellDisplay - all values needed to render a cell.
 */
export interface CellDisplayResult {
  text: string;
  tier: string;
}

/**
 * Get all display values for a table cell.
 */
export function getCellDisplay(
  entropy: number,
  hashKey: string,
  gpuCount: number
): CellDisplayResult {
  const crackTime = calculateCrackTime(entropy, hashKey, gpuCount);

  return {
    text: formatCrackTime(crackTime),
    tier: getCrackTimeTier(crackTime),
  };
}

/**
 * Get a human-readable description of password strength.
 */
export function getStrengthLabel(entropy?: number): string {
  if (entropy === undefined) return '-';
  if (entropy < 28) return 'Very Weak';
  if (entropy < 36) return 'Weak';
  if (entropy < 60) return 'Moderate';
  if (entropy < 80) return 'Strong';
  if (entropy < 100) return 'Very Strong';
  return 'Excellent';
}

/**
 * Get tier class for entropy strength.
 */
export function getStrengthTier(entropy?: number): string {
  if (entropy === undefined) return '';
  if (entropy < 28) return 'tier-2';
  if (entropy < 36) return 'tier-2'; // ^^ red
  if (entropy < 60) return 'tier-3'; // yellow
  if (entropy < 80) return 'tier-5'; // .. green
  return 'tier-5';
}

/**
 * SHA-1 hash a password and return the hex string.
 * Works in both browser and Node.js environments.
 */
async function sha1Hash(password: string): Promise<string> {
  if (typeof globalThis.crypto?.subtle !== 'undefined') {
    // Browser environment
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  } else {
    // Node.js environment (build time)
    const { createHash } = await import('node:crypto');
    return createHash('sha1').update(password).digest('hex').toUpperCase();
  }
}

/**
 * Query the HIBP API with a hash prefix and find the count for a given suffix.
 */
async function queryHIBPRange(prefix: string, suffix: string, signal?: AbortSignal): Promise<number> {
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }, // Prevent response length analysis
      signal,
    });

    if (!response.ok) return 0;

    const text = await response.text();
    // Response format: "SUFFIX:COUNT\r\n" per line
    for (const line of text.split('\r\n')) {
      const [lineSuffix, count] = line.split(':');
      if (lineSuffix === suffix) {
        return parseInt(count, 10);
      }
    }
  } catch {
    // Network error or aborted, fail silently
    return 0;
  }

  return 0;
}

/**
 * Check if a password has been exposed in data breaches using HIBP k-anonymity API.
 * Returns the number of times the password was seen in breaches, or 0 if not found.
 * Accepts an optional AbortSignal to cancel in-flight requests.
 * Works in both browser and Node.js (build time) environments.
 */
export async function checkHIBP(password: string, signal?: AbortSignal): Promise<number> {
  if (password.length === 0) return 0;

  const hashHex = await sha1Hash(password);

  // k-anonymity: send only first 5 chars of hash
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  return queryHIBPRange(prefix, suffix, signal);
}

/**
 * Format HIBP breach count for display.
 */
export function formatBreachCount(count: number): string {
  if (count === 0) return 'None';
  if (count < 10000) return `${count}`;
  if (count < 1000000) return `${(count / 1000).toFixed(0)}k`;
  return `${(count / 1000000).toFixed(1)}M`;
}

/**
 * Get tier class for breach count.
 */
export function getBreachTier(count: number): string {
  if (count === 0) return 'tier-5';  // Green - safe
  if (count < 10) return 'tier-2';   // Orange - seen a few times
  return 'tier-2';                     // Purple/Red - heavily compromised
}

/**
 * Result of penalized entropy calculation.
 */
export interface PenalizedEntropyResult {
  entropy: number;
  isPenalized: boolean;
}

/**
 * Calculate penalized entropy based on breach count using Zipf's law.
 *
 * Attackers try passwords in order of popularity. Password frequency follows
 * Zipf's law: frequency(rank) = C / rank^s
 *
 * From "A Large-Scale Study of Web Password Habits" (Florêncio & Herley) and
 * subsequent research (https://arxiv.org/pdf/1104.3722), s ≈ 0.78 for passwords.
 *
 * Given a password's breach count (frequency), we estimate its rank in the
 * attacker's priority list, then compute entropy as log2(rank).
 *
 * Parameters (pessimistic):
 * - C = 1,000,000 (frequency of "password", not the highest like "123456" at 42M)
 * - s = 0.78 (Zipf exponent from research)
 *
 * Formula: rank = (C / frequency)^(1/s), entropy = log2(rank)
 *
 * Examples:
 * - 42M breaches ("123456"): rank ≈ 1 → entropy ≈ 0 bits
 * - 1M breaches ("password"): rank ≈ 1 → entropy ≈ 0 bits
 * - 100K breaches: rank ≈ 19 → entropy ≈ 4.2 bits
 * - 10K breaches: rank ≈ 363 → entropy ≈ 8.5 bits
 * - 1K breaches: rank ≈ 6,918 → entropy ≈ 12.8 bits
 * - 100 breaches: rank ≈ 132K → entropy ≈ 17 bits
 * - 10 breaches: rank ≈ 2.5M → entropy ≈ 21.3 bits
 * - 1 breach: rank ≈ 48M → entropy ≈ 25.5 bits
 */
export function calculatePenalizedEntropy(
  originalEntropy: number,
  breachCount: number
): PenalizedEntropyResult {
  if (breachCount === 0) {
    return { entropy: originalEntropy, isPenalized: false };
  }

  // Zipf's law parameters (pessimistic estimates)
  const C = 1_000_000;  // Frequency of "password" (~1M occurrences)
  const s = 0.78;       // Zipf exponent from password research

  // Estimate rank from frequency: rank = (C / frequency)^(1/s)
  // Cap frequency at C to avoid rank < 1 for very common passwords
  const frequency = Math.min(breachCount, C);
  const rank = Math.max(1, Math.pow(C / frequency, 1 / s));

  // Entropy is log2(rank) - the number of guesses to reach this password
  const penalizedEntropy = Math.log2(rank);

  // A hard cap on the maximum entropy for breached passwords.
  // Password breach sets are around 1B passwords in size, log2(1B) = 30 bits of entropy. We want
  // to be conservative if the attacker has a more tailored breach list.
  const breachedEntropyCap = 25.0;

  // Use the lower of original entropy or the Zipf-estimated entropy, with a hard cap of 25 bits
  console.debug('Calculated penalty', { frequency, rank, penalizedEntropy, originalEntropy, breachedEntropyCap });
  const finalEntropy = Math.min(originalEntropy, penalizedEntropy, breachedEntropyCap);

  return {
    entropy: finalEntropy,
    isPenalized: breachCount > 0,
  };
}
