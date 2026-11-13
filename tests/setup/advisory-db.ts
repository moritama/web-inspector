/**
 * Vitest の setupFiles（v1.8.0 T01）
 *
 * 検出・照合のテストが、同梱 DB（src/detection/advisory-db.json）の中身に左右されないよう、
 * 既定の照合 DB を固定 DB（tests/fixtures/advisory-db.fixture.json）に差し替える。
 * 各テストの前に毎回差し替え直すので、あるテストが setTestAdvisoryDatabase(null) で戻しても、次のテストには影響しない。
 * vite.config.ts の test.setupFiles から読み込まれる。
 */
import { beforeEach } from 'vitest';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../../src/detection/advisory';
import rawFixtureDb from '../fixtures/advisory-db.fixture.json';

export const FIXTURE_ADVISORY_DB = rawFixtureDb as unknown as AdvisoryDatabase;

setTestAdvisoryDatabase(FIXTURE_ADVISORY_DB);

beforeEach(() => {
  setTestAdvisoryDatabase(FIXTURE_ADVISORY_DB);
});
