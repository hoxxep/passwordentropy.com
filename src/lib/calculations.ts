// Password entropy and crack time calculations

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
  { label: 'None (plaintext)', key: 'none' },
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
 * Calculate password entropy in bits.
 * Entropy = log2(charsetSize ^ length) = length * log2(charsetSize)
 */
export function calculateEntropy(password: string): number {
  if (password.length === 0) return 0;

  const analysis = analyzePassword(password);
  if (analysis.charsetSize === 0) return 0;

  return analysis.length * Math.log2(analysis.charsetSize);
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
  if (seconds === 0) return 'Instant';
  if (seconds < 0.001) return 'Instant';
  if (seconds < 1) return '<1 sec';
  if (seconds < 60) return `${Math.round(seconds)} sec`;

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

  if (years < 1e6) return `${(years / 1000).toFixed(1)}k yrs`;
  if (years < 1e9) return `${(years / 1e6).toFixed(1)}M yrs`;
  if (years < 1e12) return `${(years / 1e9).toFixed(1)}B yrs`;
  if (years < 1e15) return `${(years / 1e12).toFixed(1)}T yrs`;

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
  if (seconds < 600) return 'tier-1';              // < 10 minutes (instant)
  if (seconds < 31557600) return 'tier-2';         // < 1 year
  if (seconds < 3.1557e12) return 'tier-3';        // < 100k years
  if (seconds < 3.1557e17) return 'tier-4';        // < 10 billion years
  return 'tier-5';                                  // >= 10 billion years
}

/**
 * Get opacity based on crack time - fade extremes.
 */
export function getCrackTimeOpacity(seconds: number): number {
  // Don't fade, all values are meaningful for this use case
  return 1;
}

/**
 * Result of getCellDisplay - all values needed to render a cell.
 */
export interface CellDisplayResult {
  text: string;
  opacity: number;
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
    opacity: getCrackTimeOpacity(crackTime),
    tier: getCrackTimeTier(crackTime),
  };
}

/**
 * Get a human-readable description of password strength.
 */
export function getStrengthLabel(entropy: number): string {
  if (entropy === 0) return 'None';
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
export function getStrengthTier(entropy: number): string {
  if (entropy === 0) return '';
  if (entropy < 28) return 'tier-1';
  if (entropy < 36) return 'tier-2';
  if (entropy < 60) return 'tier-3';
  if (entropy < 80) return 'tier-4';
  return 'tier-5';
}
