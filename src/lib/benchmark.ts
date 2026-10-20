// In-browser benchmarking of password hashing algorithms, for the /speed page.
//
// Hashes run in Web Workers so the page stays responsive and a run can be cancelled by
// terminating the worker. PBKDF2 uses WebCrypto (native code, like a server's OpenSSL);
// bcrypt, scrypt and Argon2id use hash-wasm, which benchmarks close to native libargon2.

export interface SpeedAlgorithm {
  key: string;
  label: string;
}

// Strongest first: these are the algorithms worth tuning for password storage.
export const speedAlgorithms: SpeedAlgorithm[] = [
  { key: 'argon2id', label: 'Argon2id' },
  { key: 'scrypt', label: 'scrypt' },
  { key: 'bcrypt', label: 'bcrypt' },
  { key: 'pbkdf2', label: 'PBKDF2-SHA256' },
];

/**
 * A single hash for a worker to compute. Argon2id jobs describe one lane: see `planJobs`.
 */
export type HashJob =
  | { algo: 'pbkdf2'; iterations: number }
  | { algo: 'bcrypt'; cost: number }
  | { algo: 'scrypt'; N: number; r: number; p: number }
  | { algo: 'argon2id'; memoryKiB: number; iterations: number };

export interface WorkerRequest {
  id: number;
  job: HashJob;
  reps: number;
}

export type WorkerResponse =
  | { id: number; ms: number }
  | { id: number; error: string };

// hash-wasm backs Argon2id memory with a single typed array, which tops out just under 2 GiB.
export const MAX_ARGON2_LANE_MIB = 2047;

/**
 * Split a hash into the jobs that run concurrently, one per worker.
 *
 * Browser Argon2id libraries (hash-wasm included) compute lanes one after another, whereas
 * libargon2 on a server gives each lane its own thread. Argon2 lanes only synchronise four
 * times per pass, so p workers each filling m/p memory concurrently is a close stand-in:
 * it lands within ~10% of native multithreaded libargon2 across p = 1..8.
 *
 * scrypt's p is computed sequentially by most server libraries (OpenSSL, hashlib), so it
 * stays a single job that simply does p times the work.
 */
export function planJobs(algo: string, params: Record<string, number>): HashJob[] {
  switch (algo) {
    case 'pbkdf2':
      return [{ algo, iterations: params.iterations }];
    case 'bcrypt':
      return [{ algo, cost: params.cost }];
    case 'scrypt':
      return [{ algo, N: params.N, r: params.r, p: params.p }];
    case 'argon2id': {
      const lanes = params.parallelism;
      // Argon2 needs at least 8 KiB (8 blocks) per lane
      const memoryKiB = Math.max(8, Math.floor((params.memory * 1024) / lanes));
      return Array.from({ length: lanes }, () => ({ algo, memoryKiB, iterations: params.iterations }));
    }
    default:
      throw new Error(`Unknown algorithm: ${algo}`);
  }
}

/**
 * Explain why parameters can't be benchmarked in the browser, or null if they can.
 */
export function paramsProblem(algo: string, params: Record<string, number>): string | null {
  if (algo === 'scrypt' && (params.N & (params.N - 1)) !== 0) {
    return 'scrypt N must be a power of two.';
  }
  if (algo === 'argon2id' && params.memory / params.parallelism > MAX_ARGON2_LANE_MIB) {
    return 'Browsers cap each Argon2id lane at 2 GiB. Lower the memory or raise parallelism.';
  }
  return null;
}

/**
 * Memory one hash holds while it runs, in bytes.
 */
export function memoryPerHash(algo: string, params: Record<string, number>): number {
  switch (algo) {
    case 'argon2id':
      return params.memory * 1024 * 1024;
    case 'scrypt':
      // V is N blocks of 128 * r bytes; the p lanes run one at a time and reuse it
      return 128 * params.N * params.r;
    case 'bcrypt':
      return 4168;  // Blowfish S-boxes and P-array
    default:
      return 0;
  }
}

export interface Measurement {
  /** Wall-clock time for one hash: the login latency a user would see. */
  wallMs: number;
  /** CPU time for one hash, summed across threads: what it costs the server. */
  cpuMs: number;
}

export class BenchmarkCancelled extends Error {
  constructor() {
    super('Benchmark cancelled');
  }
}

interface Pending {
  resolve: (ms: number) => void;
  reject: (error: Error) => void;
}

export interface MeasureOptions {
  /** Keep sampling until roughly this much time has been spent, after the warm-up. */
  budgetMs?: number;
  minRounds?: number;
}

/**
 * Runs hash jobs on a pool of workers. `cancel()` terminates any run in progress, and the
 * pool is rebuilt on the next measurement.
 */
export class BenchmarkRunner {
  private workers: Worker[] = [];
  private pending = new Map<number, Pending>();
  private nextId = 0;

  readonly cores = Math.max(1, navigator.hardwareConcurrency || 1);

  private worker(index: number): Worker {
    while (this.workers.length <= index) {
      const worker = new Worker(new URL('./benchmark.worker.ts', import.meta.url), { type: 'module' });
      worker.addEventListener('message', (event: MessageEvent<WorkerResponse>) => {
        const response = event.data;
        const pending = this.pending.get(response.id);
        if (!pending) return;
        this.pending.delete(response.id);
        if ('error' in response) pending.reject(new Error(response.error));
        else pending.resolve(response.ms);
      });
      // A worker that dies (e.g. the tab ran out of memory) can't answer anything it was sent
      worker.addEventListener('error', event => {
        event.preventDefault();
        this.rejectAll(new Error(event.message || 'The benchmark worker crashed, likely out of memory.'));
      });
      this.workers.push(worker);
    }
    return this.workers[index];
  }

  private rejectAll(error: Error) {
    const pending = [...this.pending.values()];
    this.pending.clear();
    pending.forEach(p => p.reject(error));
  }

  cancel() {
    this.workers.forEach(worker => worker.terminate());
    this.workers = [];
    this.rejectAll(new BenchmarkCancelled());
  }

  private send(index: number, job: HashJob, reps: number): Promise<number> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const request: WorkerRequest = { id, job, reps };
      this.worker(index).postMessage(request);
    });
  }

  /**
   * Run every job concurrently `reps` times and report the per-hash timings.
   */
  private async round(jobs: HashJob[], reps: number): Promise<Measurement> {
    const start = performance.now();
    const workerMs = await Promise.all(jobs.map((job, i) => this.send(i, job, reps)));
    const wallMs = (performance.now() - start) / reps;

    // Each worker times itself, so the sum is CPU time. With more threads than cores they
    // also time each other's turns, so never claim more CPU than the cores could provide.
    const cpuMs = Math.min(workerMs.reduce((a, b) => a + b, 0), wallMs * reps * this.cores) / reps;
    return { wallMs, cpuMs };
  }

  /**
   * Benchmark one hash with the given parameters: a warm-up round (which also loads the
   * WebAssembly), then the median of several rounds. Fast hashes repeat inside each round so
   * timer resolution and messaging overhead don't dominate.
   */
  async measure(algo: string, params: Record<string, number>, options: MeasureOptions = {}): Promise<Measurement> {
    const { budgetMs = 1000, minRounds = 3 } = options;
    const jobs = planJobs(algo, params);

    const warmup = await this.round(jobs, 1);
    // A slow hash is its own best measurement, there's no need to keep the visitor waiting
    if (warmup.wallMs >= 1000) return warmup;

    const reps = Math.min(1000, Math.max(1, Math.ceil(25 / Math.max(warmup.wallMs, 0.01))));
    const rounds: Measurement[] = [];
    let elapsed = 0;
    while (rounds.length < minRounds || (elapsed < budgetMs && rounds.length < 15)) {
      const measurement = await this.round(jobs, reps);
      rounds.push(measurement);
      elapsed += measurement.wallMs * reps;
    }

    rounds.sort((a, b) => a.wallMs - b.wallMs);
    return rounds[Math.floor(rounds.length / 2)];
  }
}

/**
 * Format a duration in milliseconds, e.g. "0.42 ms", "123 ms", "1.2 s".
 */
export function formatMs(ms: number): string {
  if (ms < 10) return `${ms.toFixed(2)} ms`;
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
  return `${(ms / 60_000).toFixed(1)} min`;
}

/**
 * Format a byte count, e.g. "4 KiB", "64 MiB", "1.5 GiB".
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '< 1 KiB';
  const units: [number, string][] = [[2 ** 30, 'GiB'], [2 ** 20, 'MiB'], [2 ** 10, 'KiB']];
  for (const [size, unit] of units) {
    if (bytes >= size) {
      const scaled = bytes / size;
      return `${Number.isInteger(scaled) || scaled >= 10 ? Math.round(scaled) : scaled.toFixed(1)} ${unit}`;
    }
  }
  return `${bytes} B`;
}
