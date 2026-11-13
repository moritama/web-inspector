/**
 * 検出・照合のテストの既定 DB が固定 DB であること（v1.8.0 T01）
 *
 * vite.config.ts の test.setupFiles に tests/setup/advisory-db.ts が入り、
 * 各テストの前に setTestAdvisoryDatabase(固定 DB) が呼ばれていることを、照合の結果から確かめる。
 * このファイルでは、意図して setTestAdvisoryDatabase を呼ばない（最後の 2 件を除く）。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { AdvisoryDatabase, matchOfflineAdvisories, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { REPO_ROOT } from './helpers/release-version';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

const fixtureDb = rawFixtureDb as unknown as AdvisoryDatabase;

describe('既定の照合 DB は固定 DB（tests/fixtures/advisory-db.fixture.json）', () => {
  it('vite.config.ts の test.setupFiles に tests/setup/advisory-db.ts が指定されていること', () => {
    const config = fs.readFileSync(path.join(REPO_ROOT, 'vite.config.ts'), 'utf-8');
    expect(config).toMatch(/setupFiles/);
    expect(config).toMatch(/tests\/setup\/advisory-db(\.ts)?['"]/);
  });

  it('DB を渡さずに照合すると、固定 DB の dataVersion と収録件数が使われること（陽性）', () => {
    const result = matchOfflineAdvisories('Apache', '2.4.62');
    expect(result.advisoryDataVersion).toBe(fixtureDb.dataVersion);
    expect(result.productAdvisoryCount).toBe(fixtureDb.libraries.apache.versions.length);
  });

  it('固定 DB の内容どおりに照合されること（固定 DB にある範囲に入る版は該当）', () => {
    const result = matchOfflineAdvisories('Apache', '2.4.49');
    expect(result.matchStatus).toBe('Potentially Affected');
    const fixtureCves = fixtureDb.libraries.apache.versions.map((v) => v.cve);
    for (const adv of result.advisories) {
      expect(fixtureCves).toContain(adv.id);
    }
  });

  it('DB を明示的に渡したときは、既定の固定 DB より渡した DB が優先されること（陰性: 既定が上書きを妨げない）', () => {
    const syntheticDb: Partial<AdvisoryDatabase> = {
      dataVersion: '20000101',
      generatedAt: new Date().toISOString(),
      libraries: { apache: { ...fixtureDb.libraries.apache, versions: fixtureDb.libraries.apache.versions.slice(0, 1) } },
    };
    const result = matchOfflineAdvisories('Apache', '2.4.62', syntheticDb);
    expect(result.advisoryDataVersion).toBe('20000101');
    expect(result.productAdvisoryCount).toBe(1);
  });

  it('あるテストで setTestAdvisoryDatabase(null) を呼んでも…', () => {
    setTestAdvisoryDatabase(null);
    expect(true).toBe(true);
  });

  it('…次のテストでは、既定の固定 DB に戻っていること（各テストの前に差し替え直す）', () => {
    const result = matchOfflineAdvisories('Apache', '2.4.62');
    expect(result.advisoryDataVersion).toBe(fixtureDb.dataVersion);
    expect(result.productAdvisoryCount).toBe(fixtureDb.libraries.apache.versions.length);
  });
});
