/**
 * PRIVA-FISC v0-A — foundation regression-guard runner (`npm test`).
 * ============================================================================
 * Imports every guard module (side-effect test registration), then runs them.
 * NOT the ZK circuit — plain spec-correctness + anti-drift regression guards.
 * ----------------------------------------------------------------------------
 */

import './t-order.test.js';
import './t-leak.test.js';
import './t-det.test.js';
import './t-canon.test.js';
import './t-range.test.js';
import './t-d5.test.js';
import './t-purity.test.js';

import { runAll } from './harness.js';

await runAll();
