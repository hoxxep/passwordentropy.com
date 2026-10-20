// Tests for the /speed page's benchmark planning. The hashing itself runs in Web Workers.

import { describe, test, expect } from 'vitest';

import { planJobs, paramsProblem, memoryPerHash, formatMs, formatBytes } from '@lib/benchmark';

describe('planJobs', () => {
  test('splits Argon2id into one job per lane, sharing the memory', () => {
    const jobs = planJobs('argon2id', { memory: 64, iterations: 3, parallelism: 4 });
    expect(jobs).toHaveLength(4);
    for (const job of jobs) expect(job).toEqual({ algo: 'argon2id', memoryKiB: 16384, iterations: 3 });
  });

  test('keeps scrypt parallelism inside a single sequential job', () => {
    expect(planJobs('scrypt', { N: 16384, r: 8, p: 2 })).toEqual([{ algo: 'scrypt', N: 16384, r: 8, p: 2 }]);
  });

  test('gives every Argon2id lane the 8 KiB minimum', () => {
    const jobs = planJobs('argon2id', { memory: 8, iterations: 1, parallelism: 64 });
    expect(jobs.every(job => job.algo === 'argon2id' && job.memoryKiB >= 8)).toBe(true);
  });
});

describe('paramsProblem', () => {
  test('rejects scrypt N that is not a power of two', () => {
    expect(paramsProblem('scrypt', { N: 10000, r: 8, p: 1 })).not.toBeNull();
    expect(paramsProblem('scrypt', { N: 16384, r: 8, p: 1 })).toBeNull();
  });

  test('rejects Argon2id lanes over the browser memory cap', () => {
    expect(paramsProblem('argon2id', { memory: 4096, iterations: 3, parallelism: 1 })).not.toBeNull();
    expect(paramsProblem('argon2id', { memory: 4096, iterations: 3, parallelism: 2 })).not.toBeNull();
    expect(paramsProblem('argon2id', { memory: 4096, iterations: 3, parallelism: 4 })).toBeNull();
  });
});

describe('memoryPerHash', () => {
  test('matches each algorithm\'s memory layout', () => {
    expect(memoryPerHash('argon2id', { memory: 64, iterations: 3, parallelism: 4 })).toBe(64 * 2 ** 20);
    // 128 * N * r, the p lanes reuse the same buffer
    expect(memoryPerHash('scrypt', { N: 2 ** 17, r: 8, p: 4 })).toBe(128 * 2 ** 20);
    expect(memoryPerHash('pbkdf2', { iterations: 600_000 })).toBe(0);
  });
});

describe('formatting', () => {
  test('formatMs', () => {
    expect(formatMs(0.4219)).toBe('0.42 ms');
    expect(formatMs(123.4)).toBe('123 ms');
    expect(formatMs(1234)).toBe('1.23 s');
    expect(formatMs(90_000)).toBe('1.5 min');
  });

  test('formatBytes', () => {
    expect(formatBytes(64 * 2 ** 20)).toBe('64 MiB');
    expect(formatBytes(1.5 * 2 ** 30)).toBe('1.5 GiB');
    expect(formatBytes(4168)).toBe('4.1 KiB');
  });
});
