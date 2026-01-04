// Password entropy and crack time calculations

// Hash rates per GPU (hashes per second) based on RTX 4090 benchmarks
// Sources: hashcat benchmarks, various security research
export const hashRates: Record<string, number> = {
  none: 1e12,           // Plain text comparison: ~1 trillion/s
  md5: 164e9,           // ~164 billion/s
  sha1: 27e9,           // ~27 billion/s
  sha512: 3.5e9,        // ~3.5 billion/s
  pbkdf2: 30e3,         // ~30k/s (PBKDF2-HMAC-SHA256, 100k iterations)
  bcrypt: 184e3,        // ~184k/s (cost factor 10)
  scrypt: 2.8e6,        // ~2.8 million/s (default params)
  argon2id: 19.7e3,     // ~20k/s (default params)
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
