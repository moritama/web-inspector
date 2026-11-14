/**
 * v1.8.1 T02: distro 節（schema 2.3）の固定 DB と、distro 節の無い旧 DB の互換
 *
 * - 固定 DB（tests/fixtures/advisory-db.fixture.json）に distro 節がある（T03・T06 のテストが使う）。その形が validateDb を通ること
 * - distro 節の無い旧 DB（schema 2.2）を渡しても、拡張の照合はこれまでどおり（第1段階の表示）動くこと（受け入れ条件 3 の後半、§5.3）
 * - DB の版・件数・日付は直接書かない
 */
import { describe, expect, it } from 'vitest';
import * as crypto from 'crypto';
import type { AdvisoryDistroSection } from '../src/shared/types';
import { AdvisoryDatabase, getAdvisoryDbMetadata, matchOfflineAdvisories, setTestAdvisoryDatabase } from '../src/detection/advisory';
// @ts-expect-error scripts/validate-advisories.mjs は型定義を持たない .mjs モジュール
import { validateDb } from '../scripts/validate-advisories.mjs';
// @ts-expect-error scripts/ci/rehearse-db-release.mjs は型定義を持たない .mjs モジュール
import { bumpAdvisoryDb } from '../scripts/ci/rehearse-db-release.mjs';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

type FixtureDb = AdvisoryDatabase & {
  distro?: AdvisoryDistroSection;
  integrity?: { algorithm: string; target: string; digest: string; distroDigest?: string };
  [key: string]: unknown;
};

const fixture = rawFixtureDb as unknown as FixtureDb;
const sha256 = (text: string): string => crypto.createHash('sha256').update(text).digest('hex');

/** distro 節を外し、schema を 2.2 に戻した旧 DB */
function legacyDb(): FixtureDb {
  const db = structuredClone(fixture);
  delete db.distro;
  db.schemaVersion = '2.2';
  if (db.integrity) delete db.integrity.distroDigest;
  return db;
}

describe('T02: 固定 DB の distro 節', () => {
  it('固定 DB は schema 2.3 で、distro 節に releases と map（どちらも空でない配列）があること', () => {
    expect(fixture.schemaVersion).toBe('2.3');
    expect(fixture.distro).toBeDefined();
    expect(Array.isArray(fixture.distro?.releases) && (fixture.distro?.releases.length ?? 0) > 0).toBe(true);
    expect(Array.isArray(fixture.distro?.map) && (fixture.distro?.map.length ?? 0) > 0).toBe(true);
  });

  it('固定 DB の integrity は libraries と distro の両方と一致すること（固定 DB の手入れ漏れの検出）', () => {
    expect(fixture.integrity?.digest).toBe(sha256(JSON.stringify(fixture.libraries)));
    expect(fixture.integrity?.distroDigest).toBe(sha256(JSON.stringify(fixture.distro)));
  });

  it('固定 DB の distro 節は validateDb の検査を通ること（対応表の全項目に evidenceUrl と verifiedAt がある）', () => {
    for (const e of fixture.distro?.map ?? []) {
      expect(e.evidenceUrl.startsWith('https://')).toBe(true);
      expect(e.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
    expect(() => validateDb({ ...fixture, integrity: undefined })).not.toThrow();
  });

  it('固定 DB のライフサイクルには、標準サポート終了と延長サポート終了の項目があること', () => {
    for (const r of fixture.distro?.releases ?? []) {
      expect(r.release).toBe(`${r.family}:${r.cycle}`);
      expect('standardSupportEnd' in r).toBe(true);
      expect('extendedSupportEnd' in r).toBe(true);
    }
  });

  it('DB だけのリリースの予行と同じ処理（bumpAdvisoryDb）を固定 DB にかけると、distro 節はそのままで distroDigest が計算し直されること', () => {
    const bumped = bumpAdvisoryDb(structuredClone(fixture)) as FixtureDb;
    expect(bumped.distro).toEqual(fixture.distro);
    expect(bumped.integrity?.distroDigest).toBe(sha256(JSON.stringify(fixture.distro)));
    expect(bumped.integrity?.digest).toBe(sha256(JSON.stringify(fixture.libraries)));
  });
});

describe('T02: distro 節の無い旧 DB でも拡張は動く（§5.3）', () => {
  it('旧 DB（schema 2.2・distro 節なし）は validateDb を通ること', () => {
    expect(() => validateDb({ ...legacyDb(), integrity: undefined })).not.toThrow();
  });

  it('旧 DB で、ディストリ版の Apache は第1段階どおり Needs Review（上流版での参考件数あり）、上流の版は照合されること', () => {
    const db = legacyDb();
    const ubuntuApache = matchOfflineAdvisories('Apache', 'Apache/2.4.41 (Ubuntu)', db);
    expect(ubuntuApache.matchStatus).toBe('Needs Review');
    expect(ubuntuApache.advisories).toHaveLength(0);
    expect(ubuntuApache.upstreamAdvisoriesCount).toBeGreaterThan(0);

    const upstream = matchOfflineAdvisories('Apache', '2.4.49', db);
    expect(upstream.matchStatus).toBe('Potentially Affected');
  });

  it('旧 DB を既定の照合 DB に差し替えても、照合とメタデータの取得が例外を投げないこと', () => {
    setTestAdvisoryDatabase(legacyDb());
    expect(() => matchOfflineAdvisories('nginx', 'nginx/1.18.0 (Ubuntu)')).not.toThrow();
    expect(() => matchOfflineAdvisories('PHP', '7.4.3-4ubuntu2.19')).not.toThrow();
    expect(() => getAdvisoryDbMetadata()).not.toThrow();
  });
});
