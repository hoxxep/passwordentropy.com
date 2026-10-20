// Web Worker for the /speed page: computes hashes on request and reports how long they took.

/// <reference lib="webworker" />

import { argon2id, bcrypt, scrypt } from 'hash-wasm';
import type { HashJob, WorkerRequest, WorkerResponse } from '@lib/benchmark';

// Inputs don't affect timing, so fixed ones keep runs comparable
const password = 'correct horse battery staple';
const passwordBytes = new TextEncoder().encode(password);
const salt = new Uint8Array(16).fill(0x5a);

let pbkdf2Key: Promise<CryptoKey> | undefined;

async function hashOnce(job: HashJob): Promise<void> {
  switch (job.algo) {
    case 'pbkdf2':
      pbkdf2Key ??= crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: job.iterations },
        await pbkdf2Key,
        256
      );
      return;
    case 'bcrypt':
      await bcrypt({ password, salt, costFactor: job.cost, outputType: 'binary' });
      return;
    case 'scrypt':
      await scrypt({
        password, salt, costFactor: job.N, blockSize: job.r, parallelism: job.p,
        hashLength: 32, outputType: 'binary',
      });
      return;
    case 'argon2id':
      // One lane of a parallel hash, see planJobs
      await argon2id({
        password, salt, memorySize: job.memoryKiB, iterations: job.iterations, parallelism: 1,
        hashLength: 32, outputType: 'binary',
      });
      return;
  }
}

self.addEventListener('message', async (event: MessageEvent<WorkerRequest>) => {
  const { id, job, reps } = event.data;
  let response: WorkerResponse;
  try {
    const start = performance.now();
    for (let i = 0; i < reps; i++) await hashOnce(job);
    response = { id, ms: performance.now() - start };
  } catch (error) {
    response = { id, error: error instanceof Error ? error.message : String(error) };
  }
  self.postMessage(response);
});
