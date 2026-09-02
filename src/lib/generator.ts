// Passphrase generation.
//
// Words come from the Orchard Street Long wordlist in full: 17,576 words (26^3, so
// 14.10 bits per word), 3-15 characters each. See src/assets/wordlist.txt.
//
// The list is *uniquely decodable*: any concatenation of words from it can only be split
// back apart one way. That is what makes it safe to join words with no separator — an
// ambiguous list would quietly lose entropy to alternative readings (in + put = input).
//
// Source: https://github.com/sts10/orchard-street-wordlists (CC BY-SA 4.0, Sam Schlinkert)

// `?url` emits the list as a separate, content-hashed asset and gives us its URL as a plain
// string. The import costs nothing at page load — the bytes are only fetched by loadWordlist(),
// and the hashed filename means the browser can cache them forever.
import wordlistUrl from '@assets/wordlist.txt?url';

/** Static asset, fetched on first use rather than bundled into the page JS. */
export const WORDLIST_URL = wordlistUrl;

/** Words per generated passphrase. */
export const DEFAULT_WORD_COUNT = 4;

/** Joined with no separator: fewer keystrokes, and the wordlist stays unambiguous without one. */
export const WORD_SEPARATOR = '';

/**
 * Longest passphrase we hand out, expressed per word — four words are capped at 36 characters.
 *
 * The wordlist runs from 3 to 15 characters, so an unconstrained four-word draw lands anywhere
 * from 12 to 60 characters. The long tail is the part worth removing: a 43-character passphrase
 * is a great deal slower to type than a 30-character one and is no stronger for it.
 *
 * Capping the total is much cheaper than dropping long words from the list. Excluding every
 * word over 9 characters would leave 13,130 words and cost 1.69 bits at four words; capping the
 * total at the same 36 characters costs 0.26 bits, because it only has to reject the draws that
 * come out long overall rather than every draw that happens to contain one long word.
 */
export const MAX_CHARS_PER_WORD = 9;

/** The character ceiling applied to a passphrase of `wordCount` words. */
export function maxPassphraseLength(wordCount: number): number {
  return MAX_CHARS_PER_WORD * wordCount;
}

/**
 * Candidates are re-rolled until they fit the length ceiling and — when an independent
 * estimator is supplied — score below the entropy we actually put in, so we never hand out a
 * passphrase that is a chore to type or whose strength we would then overstate.
 *
 * Rejecting on content-dependent tests shrinks the keyspace: we are no longer sampling from
 * all wordlist^n passphrases, only from the accepted fraction, and an attacker who knows the
 * algorithm only has to search that fraction. So the entropy we report has to be discounted
 * by log2(acceptance rate).
 *
 * These are conservative floors on the rates measured against the shipped wordlist, rounded
 * down to leave margin. Floors rather than exact rates keep the reported entropy an honest
 * *lower* bound. tests/generator.test.ts asserts the real rates clear them.
 */
const MIN_ACCEPTANCE_RATE: Record<'length' | 'estimated', Record<number, number>> = {
  /** Length ceiling alone. Measured: 81.0 / 84.0 / 84.7 / 86.3 / 88.6 / 90.2%. */
  length: { 3: 0.72, 4: 0.75, 5: 0.76, 6: 0.78, 7: 0.80, 8: 0.82 },
  /** Length ceiling and estimator together. Measured: 69.9 / 65.8 / 59.9 / 51.8 / 43.6 / 35.3%. */
  estimated: { 3: 0.60, 4: 0.55, 5: 0.50, 6: 0.42, 7: 0.34, 8: 0.26 },
};

/** Applied to word counts with no measured floor of their own. */
const FALLBACK_ACCEPTANCE_RATE: Record<'length' | 'estimated', number> = {
  length: 0.50,
  estimated: 0.10,
};

/**
 * Re-roll limit. Only a backstop against a pathological estimator — at the measured
 * acceptance rates the odds of exhausting it are below 1 in 100 million.
 */
export const MAX_ATTEMPTS = 100;

/** In-flight or resolved wordlist fetch, so we only download it once per page load. */
let wordlistPromise: Promise<string[]> | null = null;

/**
 * Download the wordlist, caching the promise. Repeat calls reuse the first fetch; the
 * browser's HTTP cache covers subsequent page loads. A failed fetch clears the cache so
 * the next call can retry.
 */
export function loadWordlist(signal?: AbortSignal): Promise<string[]> {
  wordlistPromise ??= fetch(WORDLIST_URL, { signal })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Failed to load wordlist: ${response.status} ${response.statusText}`);
      }
      return response.text();
    })
    .then(text => {
      const words = text.split('\n').map(word => word.trim()).filter(Boolean);
      if (words.length < 2) {
        throw new Error(`Wordlist is too small to generate from: ${words.length} words`);
      }
      return words;
    })
    .catch(error => {
      wordlistPromise = null;
      throw error;
    });

  return wordlistPromise;
}

/**
 * A uniformly random integer in [0, max), from the platform CSPRNG.
 *
 * Rejects values in the final incomplete bucket rather than taking `% max` directly:
 * 2^32 is not a multiple of our wordlist size, so a plain modulo would make the first
 * few thousand words very slightly more likely than the rest.
 */
export function randomIndex(max: number): number {
  if (!Number.isInteger(max) || max < 1 || max > 0x100000000) {
    throw new Error(`randomIndex needs an integer in [1, 2^32], got ${max}`);
  }

  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);

  let value: number;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);

  return value % max;
}

/**
 * Entropy of a passphrase built by picking `wordCount` words uniformly at random,
 * with replacement, from a list of `wordlistSize` words.
 */
export function passphraseEntropy(wordlistSize: number, wordCount: number): number {
  return wordCount * Math.log2(wordlistSize);
}

/**
 * The conservative acceptance-rate floor used to discount a given word count.
 *
 * Every candidate is length-checked, so there is a floor even with no estimator in play.
 */
export function acceptanceRateFloor(wordCount: number, withEstimator = true): number {
  const test = withEstimator ? 'estimated' : 'length';
  return MIN_ACCEPTANCE_RATE[test][wordCount] ?? FALLBACK_ACCEPTANCE_RATE[test];
}

export interface GenerateOptions {
  wordCount?: number;
  /**
   * Independent strength estimate for a finished passphrase, e.g. zxcvbn. When supplied,
   * candidates scoring at or above the raw entropy are rejected and re-rolled.
   */
  estimateEntropy?: (passphrase: string) => number | undefined;
  /** Character ceiling for the finished passphrase. Defaults to `maxPassphraseLength`. */
  maxLength?: number;
  maxAttempts?: number;
}

export interface GeneratedPassphrase {
  passphrase: string;
  words: string[];
  /** Entropy of the generation process, discounted for rejection sampling. Report this one. */
  entropy: number;
  /** Entropy before the rejection discount: wordCount * log2(wordlist size). */
  rawEntropy: number;
  /** What the independent estimator scored this passphrase, when one was supplied. */
  estimatedEntropy?: number;
  /** Candidates drawn, including the accepted one. */
  attempts: number;
}

function drawWords(wordlist: string[], wordCount: number): string[] {
  return Array.from({ length: wordCount }, () => wordlist[randomIndex(wordlist.length)]);
}

/**
 * Generate a passphrase of `wordCount` random words.
 *
 * Words are drawn independently and with replacement — a repeated word is a legitimate
 * outcome, and re-rolling to avoid one would shrink the keyspace for no security gain.
 *
 * Every returned passphrase is at most `maxLength` characters, and with an `estimateEntropy`
 * function every one also satisfies `estimatedEntropy < rawEntropy`: the only return path is
 * the one that checks both. That is the guarantee that our reported entropy is never
 * contradicted by the independent estimate. Exhausting `maxAttempts` throws rather than
 * returning an unchecked passphrase, so there is no silent hole in either guarantee.
 */
export function generatePassphrase(
  wordlist: string[],
  options: GenerateOptions = {},
): GeneratedPassphrase {
  const {
    wordCount = DEFAULT_WORD_COUNT,
    estimateEntropy,
    maxLength = maxPassphraseLength(wordCount),
    maxAttempts = MAX_ATTEMPTS,
  } = options;

  if (wordlist.length < 2) {
    throw new Error(`Wordlist is too small to generate from: ${wordlist.length} words`);
  }
  if (!Number.isInteger(wordCount) || wordCount < 1) {
    throw new Error(`Cannot generate a passphrase of ${wordCount} words`);
  }

  // Catch an impossible ceiling now rather than by spinning through every attempt.
  const shortestPossible = wordCount * Math.min(...wordlist.map(word => word.length));
  if (shortestPossible > maxLength) {
    throw new Error(
      `No ${wordCount}-word passphrase fits in ${maxLength} characters (shortest is ${shortestPossible})`,
    );
  }

  const rawEntropy = passphraseEntropy(wordlist.length, wordCount);
  const entropy = rawEntropy + Math.log2(acceptanceRateFloor(wordCount, estimateEntropy !== undefined));

  for (let attempts = 1; attempts <= maxAttempts; attempts++) {
    const words = drawWords(wordlist, wordCount);
    const passphrase = words.join(WORD_SEPARATOR);

    if (passphrase.length > maxLength) continue;

    if (!estimateEntropy) {
      return { passphrase, words, entropy, rawEntropy, attempts };
    }

    const estimatedEntropy = estimateEntropy(passphrase);
    if (estimatedEntropy !== undefined && estimatedEntropy < rawEntropy) {
      return { passphrase, words, entropy, rawEntropy, estimatedEntropy, attempts };
    }
  }

  const alsoScored = estimateEntropy ? ` and scored below ${rawEntropy.toFixed(1)} bits` : '';
  throw new Error(
    `No candidate fit ${maxLength} characters${alsoScored} in ${maxAttempts} attempts`,
  );
}

/**
 * Entropy to display for a passphrase we generated ourselves.
 *
 * We know exactly how much randomness went into it, but zxcvbn scores the finished string
 * independently and lands either side of the truth: it reads recognisable words as cheap
 * dictionary hits, and unrecognised ones as expensive brute force. Showing the lower of the
 * two means the generator never claims more strength than the calculator would give the
 * same password if you typed it in yourself.
 */
export function generatedDisplayEntropy(generated: number, estimated?: number): number {
  return estimated === undefined ? generated : Math.min(generated, estimated);
}
