/// <reference types="vitest/config" />
import { getViteConfig } from 'astro/config';

// getViteConfig gives the tests the same resolution as the site: @lib/* aliases,
// import.meta.env, and TypeScript sources without a separate build step.
export default getViteConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    // zxcvbn runs thousands of times in the statistical tests
    testTimeout: 180_000,
  },
});