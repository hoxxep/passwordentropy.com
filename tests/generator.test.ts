// Tests for the passphrase generator. Run with `pnpm run test:unit`, or `pnpm test` for
// these plus `astro check`.

import { describe, test, expect, beforeAll, vi } from 'vitest';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  generatePassphrase,
  generatedDisplayEntropy,
  passphraseEntropy,
  acceptanceRateFloor,
  maxPassphraseLength,
  randomIndex,
  MAX_CHARS_PER_WORD,
  DEFAULT_WORD_COUNT,
  WORD_SEPARATOR,
  MAX_ATTEMPTS,
  type GeneratedPassphrase,
} from '@lib/generator';
import { calculateEntropy } from '@lib/calculations';

const WORDLIST_PATH = fileURLToPath(new URL('../src/assets/wordlist.txt', import.meta.url));
const WORDS = fs.readFileSync(WORDLIST_PATH, 'utf8').split('\n').map(w => w.trim()).filter(Boolean);
const WORD_SET = new Set(WORDS);
const LONGEST_WORD = Math.max(...WORDS.map(word => word.length));

/** Sorted, so every word sharing a prefix forms one run we can binary-search to. */
const SORTED_WORDS = [...WORDS].sort();

/** Word counts the shipped acceptance-rate floors cover. */
const SUPPORTED_COUNTS = [3, 4, 5, 6, 7, 8];

/** Draws per word count in the shared corpus below. */
const CORPUS_SAMPLES = 150;

const estimate = (passphrase: string) => calculateEntropy(passphrase);

/**
 * The tails of every word that strictly extends `prefix` — "in" yields "put" from "input".
 *
 * Scanning the whole list per prefix is what made the decodability proof below quadratic;
 * the sorted list turns it into a binary search plus the matches themselves.
 */
function extensionsOf(prefix: string): string[] {
  let lo = 0;
  let hi = SORTED_WORDS.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (SORTED_WORDS[mid] < prefix) lo = mid + 1;
    else hi = mid;
  }

  const tails: string[] = [];
  for (let i = lo; i < SORTED_WORDS.length && SORTED_WORDS[i].startsWith(prefix); i++) {
    if (SORTED_WORDS[i].length > prefix.length) tails.push(SORTED_WORDS[i].slice(prefix.length));
  }
  return tails;
}

/**
 * Rejection-sampled passphrases, drawn once per word count and shared by every test that
 * asserts a property of what the generator hands back.
 *
 * Each draw costs at least one zxcvbn run, and zxcvbn is by far the slowest thing in this
 * file (~2ms for four words, ~6ms for eight). Drawing one corpus and asserting over it
 * repeatedly keeps the assertions independent without paying for the draws more than once.
 */
const corpusCache = new Map<number, GeneratedPassphrase[]>();
function generatedCorpus(wordCount: number): GeneratedPassphrase[] {
  let corpus = corpusCache.get(wordCount);
  if (!corpus) {
    corpus = Array.from({ length: CORPUS_SAMPLES }, () =>
      generatePassphrase(WORDS, { wordCount, estimateEntropy: estimate }));
    corpusCache.set(wordCount, corpus);
  }
  return corpus;
}

beforeAll(() => {
  // calculations.ts logs debug stats outside a production build; keep test output readable.
  vi.spyOn(console, 'log').mockImplementation(() => {});
});

describe('wordlist asset', () => {
  test('is the list the generator documents', () => {
    expect(WORDS.length).toBe(17576);
    expect(WORD_SET.size, 'contains duplicates').toBe(WORDS.length);
  });

  test('every word is lowercase a-z and 3-15 characters', () => {
    // No hyphens or apostrophes: those would show up inside a separator-free passphrase.
    expect(WORDS.filter(word => !/^[a-z]{3,15}$/.test(word))).toEqual([]);
  });

  test('is uniquely decodable, so joining with no separator loses no entropy', () => {
    // Sardinas-Patterson: build the dangling suffixes, and if any is itself a codeword then
    // some concatenation has two readings, and the entropy of a joined passphrase is not
    // wordCount * log2(size).
    let frontier = new Set<string>();
    for (const word of WORD_SET) {
      for (let i = 1; i < word.length; i++) {
        if (WORD_SET.has(word.slice(0, i))) frontier.add(word.slice(i));
      }
    }

    const seen = new Set<string>();
    while (frontier.size > 0) {
      for (const suffix of frontier) {
        expect(WORD_SET.has(suffix), `"${suffix}" is a dangling codeword`).toBe(false);
      }

      const next = new Set<string>();
      for (const suffix of frontier) {
        if (seen.has(suffix)) continue;
        seen.add(suffix);
        // A codeword extending this suffix...
        for (const tail of extensionsOf(suffix)) next.add(tail);
        // ...or a codeword this suffix extends.
        for (let i = 1; i < suffix.length; i++) {
          if (WORD_SET.has(suffix.slice(0, i))) next.add(suffix.slice(i));
        }
      }
      frontier = next;
    }
  });
});

describe('randomIndex', () => {
  test('stays in range', () => {
    for (let i = 0; i < 5000; i++) {
      const value = randomIndex(WORDS.length);
      expect(Number.isInteger(value)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(WORDS.length);
    }
  });

  test('a single-element range is always 0', () => {
    for (let i = 0; i < 100; i++) expect(randomIndex(1)).toBe(0);
  });

  test('is uniform — rejection sampling, not a biased modulo', () => {
    // 13 does not divide 2^32, so `% 13` would over-represent the low indices.
    const buckets = 13;
    const draws = 130_000;
    const counts = new Array(buckets).fill(0);
    for (let i = 0; i < draws; i++) counts[randomIndex(buckets)]++;

    const expected = draws / buckets;
    const chiSquare = counts.reduce((sum, n) => sum + (n - expected) ** 2 / expected, 0);
    // df = 12; the 0.999 critical value is 32.9. A biased modulo scores far higher.
    expect(chiSquare, `distribution not uniform (chi-square ${chiSquare.toFixed(1)})`).toBeLessThan(32.9);
  });

  test('rejects nonsensical ranges', () => {
    expect(() => randomIndex(0)).toThrow();
    expect(() => randomIndex(-1)).toThrow();
    expect(() => randomIndex(2.5)).toThrow();
  });
});

describe('generatePassphrase shape', () => {
  test('returns the requested number of words, joined with no separator', () => {
    expect(WORD_SEPARATOR).toBe('');

    for (const wordCount of SUPPORTED_COUNTS) {
      const result = generatePassphrase(WORDS, { wordCount });
      expect(result.words).toHaveLength(wordCount);
      expect(result.passphrase).toBe(result.words.join(''));
      for (const word of result.words) expect(WORD_SET.has(word)).toBe(true);
    }
  });

  test('a generated passphrase decodes back to exactly the words drawn', () => {
    // The payoff of unique decodability: one reading, and it is the one we generated.
    for (let i = 0; i < 200; i++) {
      const { passphrase, words } = generatePassphrase(WORDS, { wordCount: DEFAULT_WORD_COUNT });

      const readings: string[][] = [];
      const walk = (rest: string, acc: string[]) => {
        if (rest === '') { readings.push(acc); return; }
        for (let len = 1; len <= Math.min(LONGEST_WORD, rest.length); len++) {
          const head = rest.slice(0, len);
          if (WORD_SET.has(head)) walk(rest.slice(len), [...acc, head]);
        }
      };
      walk(passphrase, []);

      expect(readings, `"${passphrase}" has ${readings.length} readings`).toHaveLength(1);
      expect(readings[0]).toEqual(words);
    }
  });

  test('rejects unusable inputs', () => {
    expect(() => generatePassphrase([])).toThrow();
    expect(() => generatePassphrase(['only'])).toThrow();
    expect(() => generatePassphrase(WORDS, { wordCount: 0 })).toThrow();
    expect(() => generatePassphrase(WORDS, { wordCount: -1 })).toThrow();
    expect(() => generatePassphrase(WORDS, { wordCount: 1.5 })).toThrow();
  });
});

describe('reported entropy', () => {
  test('with no estimator, it is discounted only for the length ceiling', () => {
    const result = generatePassphrase(WORDS, { wordCount: 4 });
    expect(result.rawEntropy).toBe(passphraseEntropy(WORDS.length, 4));
    expect(result.entropy).toBe(result.rawEntropy + Math.log2(acceptanceRateFloor(4, false)));
    expect(result.estimatedEntropy).toBeUndefined();
  });

  test('an estimator costs more entropy than the length ceiling alone', () => {
    // Both discounts are real, and stacking a second rejection test cannot be free.
    for (const wordCount of SUPPORTED_COUNTS) {
      expect(acceptanceRateFloor(wordCount, true))
        .toBeLessThan(acceptanceRateFloor(wordCount, false));
    }
  });

  test('with an estimator, it is discounted for the shrunken keyspace', () => {
    for (const wordCount of SUPPORTED_COUNTS) {
      const result = generatePassphrase(WORDS, { wordCount, estimateEntropy: estimate });
      const raw = passphraseEntropy(WORDS.length, wordCount);

      expect(result.rawEntropy).toBe(raw);
      expect(result.entropy).toBe(raw + Math.log2(acceptanceRateFloor(wordCount, true)));
      expect(result.entropy, 'rejection must cost entropy, not add it').toBeLessThan(raw);
    }
  });

  test('generatedDisplayEntropy never exceeds either input', () => {
    expect(generatedDisplayEntropy(53.4, 48.1)).toBe(48.1);
    expect(generatedDisplayEntropy(53.4, 61.2)).toBe(53.4);
    expect(generatedDisplayEntropy(53.4, undefined)).toBe(53.4);
    expect(generatedDisplayEntropy(53.4)).toBe(53.4);
  });
});

describe('the guarantee: estimated entropy stays below the entropy we put in', () => {
  test('holds for every passphrase returned, across supported word counts', () => {
    for (const wordCount of SUPPORTED_COUNTS) {
      const raw = passphraseEntropy(WORDS.length, wordCount);

      for (const result of generatedCorpus(wordCount)) {
        const estimated = result.estimatedEntropy;

        expect(estimated).toBeTypeOf('number');
        expect(
          estimated,
          `${wordCount} words: "${result.passphrase}" scored ${estimated} >= ${raw.toFixed(2)}`,
        ).toBeLessThan(raw);

        // The value the page shows is bounded by both measures.
        const shown = generatedDisplayEntropy(result.entropy, estimated);
        expect(shown).toBeLessThanOrEqual(result.entropy);
        expect(shown).toBeLessThanOrEqual(estimated as number);
      }
    }
  });

  test('is enforced by construction — an estimator that never passes throws', () => {
    expect(() => generatePassphrase(WORDS, { wordCount: 4, estimateEntropy: () => Infinity }))
      .toThrow(/No candidate fit/);

    // An estimator that cannot score the candidate is not a pass either.
    expect(() => generatePassphrase(WORDS, { wordCount: 4, estimateEntropy: () => undefined }))
      .toThrow(/No candidate fit/);
  });

  test('accepts on the first draw when the estimate is comfortably low', () => {
    // The length ceiling is lifted clear of the longest possible draw, so the estimator is
    // the only test in play and a passing one has to accept immediately.
    const result = generatePassphrase(WORDS, {
      wordCount: 4,
      maxLength: 4 * LONGEST_WORD,
      estimateEntropy: () => 1,
    });
    expect(result.attempts).toBe(1);
    expect(result.estimatedEntropy).toBe(1);
  });

  test('never exceeds the attempt cap', () => {
    for (const result of generatedCorpus(DEFAULT_WORD_COUNT)) {
      expect(result.attempts).toBeGreaterThanOrEqual(1);
      expect(result.attempts).toBeLessThanOrEqual(MAX_ATTEMPTS);
    }
  });
});

describe('the length ceiling', () => {
  test('every returned passphrase fits, across supported word counts', () => {
    for (const wordCount of SUPPORTED_COUNTS) {
      const limit = maxPassphraseLength(wordCount);
      expect(limit).toBe(MAX_CHARS_PER_WORD * wordCount);

      // Both paths through the generator apply it, with and without an estimator. The
      // estimator path is the expensive one, so it reuses the shared corpus; drawing without
      // one costs no zxcvbn call, so it gets its own, larger sample.
      const withoutEstimator = Array.from({ length: 500 }, () => generatePassphrase(WORDS, { wordCount }));

      for (const { passphrase } of [...generatedCorpus(wordCount), ...withoutEstimator]) {
        expect(passphrase.length, `"${passphrase}" is ${passphrase.length} > ${limit} chars`)
          .toBeLessThanOrEqual(limit);
      }
    }
  });

  test('it actually bites — the uncapped list would exceed it', () => {
    // Guard against the cap silently becoming a no-op if the wordlist is ever swapped out.
    const longest = LONGEST_WORD * DEFAULT_WORD_COUNT;
    expect(longest).toBeGreaterThan(maxPassphraseLength(DEFAULT_WORD_COUNT));
  });

  test('a caller-supplied ceiling is honoured', () => {
    // 28 characters is a ~24% draw, so 100 attempts effectively always find one.
    for (let i = 0; i < 100; i++) {
      expect(generatePassphrase(WORDS, { wordCount: 4, maxLength: 28 }).passphrase.length)
        .toBeLessThanOrEqual(28);
    }
  });

  test('an unsatisfiable ceiling throws rather than spinning', () => {
    // Shortest word is 3 characters, so four words cannot fit in 11.
    expect(() => generatePassphrase(WORDS, { wordCount: 4, maxLength: 11 }))
      .toThrow(/fits in 11 characters/);
  });
});

describe('acceptance-rate floors', () => {
  test('the shipped floors sit below the real rates, so reported entropy is a lower bound', () => {
    const samples = 300;

    for (const wordCount of SUPPORTED_COUNTS) {
      const raw = passphraseEntropy(WORDS.length, wordCount);
      const limit = maxPassphraseLength(wordCount);

      // Draw with no rejection at all, then measure how often each predicate would accept.
      let fitsLength = 0;
      let fitsBoth = 0;
      for (let i = 0; i < samples; i++) {
        const words = Array.from({ length: wordCount }, () => WORDS[randomIndex(WORDS.length)]);
        const passphrase = words.join(WORD_SEPARATOR);
        if (passphrase.length > limit) continue;
        fitsLength++;
        if ((estimate(passphrase) ?? Infinity) < raw) fitsBoth++;
      }

      for (const [label, accepted, withEstimator] of [
        ['length only', fitsLength, false],
        ['length + estimator', fitsBoth, true],
      ] as const) {
        const rate = accepted / samples;
        const floor = acceptanceRateFloor(wordCount, withEstimator);

        expect(
          rate,
          `${wordCount} words (${label}): measured acceptance ${(100 * rate).toFixed(1)}% is under ` +
          `the declared floor ${(100 * floor).toFixed(0)}%, so reported entropy overstates by ` +
          `${(Math.log2(floor) - Math.log2(rate)).toFixed(2)} bits`,
        ).toBeGreaterThanOrEqual(floor);
      }
    }
  });
});
