# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
pnpm install          # Install dependencies
pnpm run dev          # Start dev server at localhost:4321
pnpm run build        # Build production site to ./dist/
pnpm run preview      # Preview production build locally
pnpm run test         # Run astro check (type checking)
```

## Architecture

This is a static Astro site that calculates password entropy and estimates crack times.

### Key Files

- `src/lib/calculations.ts` - Core logic: entropy calculation, crack time estimation, hash rate constants (RTX 4090 benchmarks for MD5, SHA-1, SHA-256, SHA-512, bcrypt, scrypt, Argon2id)
- `src/pages/index.astro` - Single-page app with password input, entropy stats display, and crack time table
- `src/layouts/Layout.astro` - HTML wrapper with meta tags and analytics
- `src/global.css` - Tailwind v4 with CSS variables for theming (supports dark mode via `prefers-color-scheme`)

### Path Aliases

Configured in `tsconfig.json`:
- `@lib/*` → `src/lib/*`
- `@layouts/*` → `src/layouts/*`
- `@components/*` → `src/components/*`
- `@assets/*` → `src/assets/*`

### How It Works

1. User enters a password in the input field
2. `calculateEntropy()` analyzes character sets used (lowercase, uppercase, digits, symbols, space) and computes bits of entropy
3. `calculateCrackTime()` estimates time to crack based on entropy, hash algorithm, and GPU count
4. Table displays crack times across hash algorithms (rows) and attacker GPU scales (columns)
5. All calculations run client-side; the page is statically generated with default values
