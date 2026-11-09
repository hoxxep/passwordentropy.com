// zxcvbn configured with the English and common dictionaries.
//
// The dictionaries are ~1.7 MB of JavaScript (~800 KB gzipped), so nothing imports this module
// statically: calculations.ts pulls it in with a dynamic import() via loadEntropyEstimator(),
// which keeps it in its own chunk, off the critical path of the first page load.

import { ZxcvbnFactory, type ZxcvbnResult } from '@zxcvbn-ts/core';
import * as zxcvbnCommonPackage from '@zxcvbn-ts/language-common';
import * as zxcvbnEnPackage from '@zxcvbn-ts/language-en';

const factory = new ZxcvbnFactory({
  dictionary: {
    ...zxcvbnCommonPackage.dictionary,
    ...zxcvbnEnPackage.dictionary,
  },
  graphs: zxcvbnCommonPackage.adjacencyGraphs,
  translations: zxcvbnEnPackage.translations,
});

export const zxcvbn = (password: string): ZxcvbnResult => factory.check(password);
