import { describe, it, expect } from 'vitest';
// @ts-expect-error scripts/validate-advisories.mjs は型定義を持たない .mjs モジュール
import { isValidRange, validateDb } from '../scripts/validate-advisories.mjs';
// @ts-expect-error scripts/advisories/build-db.mjs は型定義を持たない .mjs モジュール
import { MIN_EXTENSION_VERSION, OUTPUT_SCHEMA_VERSION } from '../scripts/advisories/build-db.mjs';
import advisoryDbJson from '../src/detection/advisory-db.json';
import catalogJson from '../data/advisories/catalog.json';
import manifestJson from '../public/manifest.json';
import { AdvisoryDatabase, getAdvisoryDbMetadata, matchOfflineAdvisories } from '../src/detection/advisory';
import { compareVersions } from '../src/security/version-matcher';
import { isSameRelease, readPackageVersion, REPO_ROOT } from './helpers/release-version';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { AdvisoryDistroSection, DistroMapFile } from '../src/shared/types';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

/**
 * 同梱 DB を読んでよいテスト（tests/test-hygiene.test.ts の許可リスト）。
 * DB だけの自動リリースで中身が変わっても落ちないよう、件数・日付・特定の CVE の有無は比べない。
 * 比べるのはスキーマ・書式・不変条件と、値の出どころ（build-db.mjs・catalog.json）との一致だけ（v1.8.0 T01）。
 */

/** DB の製品の出どころ（catalog.json のキーは advisory-db.json の libraries のキーと一致させる決まり） */
const CATALOG_PRODUCTS = Object.keys((catalogJson as { products: Record<string, unknown> }).products);

describe('同梱 advisory-db.json の不変条件 (Invariants)', () => {
  it('schemaVersion が build-db の出力スキーマと一致し、基本メタデータの書式が正しいこと', () => {
    expect(advisoryDbJson.schemaVersion).toBe(OUTPUT_SCHEMA_VERSION);
    expect(advisoryDbJson.dataVersion).toMatch(/^\d{8}$/);
    expect(typeof advisoryDbJson.generatedAt).toBe('string');
    expect(Number.isNaN(Date.parse(advisoryDbJson.generatedAt))).toBe(false);
  });

  it('catalog.json の全製品が libraries に存在し（過不足なし）、それぞれ aliases / versions / eol を持つこと', () => {
    expect(CATALOG_PRODUCTS.length).toBeGreaterThan(0);
    const productKeys = Object.keys(advisoryDbJson.libraries).sort();
    expect(productKeys).toEqual([...CATALOG_PRODUCTS].sort());

    for (const key of CATALOG_PRODUCTS) {
      const lib = (advisoryDbJson.libraries as Record<string, { aliases: string[]; versions: unknown[]; eol: unknown[] }>)[key];
      expect(lib, `${key} が存在すること`).toBeDefined();
      expect(Array.isArray(lib.aliases) && lib.aliases.length > 0, `${key}.aliases が非空配列であること`).toBe(true);
      expect(Array.isArray(lib.versions) && lib.versions.length > 0, `${key}.versions が非空配列であること`).toBe(true);
      expect(Array.isArray(lib.eol) && lib.eol.length > 0, `${key}.eol が非空配列であること`).toBe(true);
    }
  });

  it('minExtensionVersion が manifest.json の version 以下であること', () => {
    expect(typeof advisoryDbJson.minExtensionVersion).toBe('string');
    expect(typeof manifestJson.version).toBe('string');
    expect(compareVersions(advisoryDbJson.minExtensionVersion, manifestJson.version)).toBeLessThanOrEqual(0);
  });

  it('同梱 advisory-db.json の全エントリの必須項目が揃い、すべての range が構文検証を通ること', () => {
    const libraries = advisoryDbJson.libraries as Record<
      string,
      {
        versions: Array<{
          cve: string;
          range: string;
          title: string;
          severity: string;
          cvssScore: number;
          fixedVersion: string | null;
          fixStatus?: string;
          advisoryUrl: string;
          verifiedAt: string;
          scoreSource: string;
        }>;
      }
    >;

    let totalChecked = 0;
    for (const [libKey, lib] of Object.entries(libraries)) {
      for (const v of lib.versions) {
        totalChecked++;
        expect(typeof v.cve === 'string' && v.cve.length > 0, `${libKey}: cve が非空文字列`).toBe(true);
        expect(typeof v.range === 'string' && v.range.length > 0, `${libKey} (${v.cve}): range が非空文字列`).toBe(true);
        expect(isValidRange(v.range), `${libKey} (${v.cve}): ${v.range} が validate-advisories の構文チェックに合格すること`).toBe(true);
        expect(typeof v.title === 'string' && v.title.length > 0, `${libKey} (${v.cve}): title が非空文字列`).toBe(true);
        expect(['critical', 'high', 'medium', 'low']).toContain(v.severity);
        expect(typeof v.cvssScore === 'number' && v.cvssScore >= 0 && v.cvssScore <= 10).toBe(true);
        expect(v.fixedVersion === null || typeof v.fixedVersion === 'string').toBe(true);
        if (v.fixStatus !== undefined) {
          expect(['fixed', 'partial', 'none', 'unknown']).toContain(v.fixStatus);
        }
        expect(v.advisoryUrl).toMatch(/^https:\/\//);
        expect(v.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(typeof v.scoreSource === 'string' && v.scoreSource.length > 0).toBe(true);
      }
    }
    expect(totalChecked).toBeGreaterThan(0);

    // エントリ半減テスト (C04c) 等で libraries のみ差し替えられた場合でも構文・構造不変条件を検証できるよう integrity は除外して validateDb に通す
    const validReport = validateDb({ ...advisoryDbJson, integrity: undefined }) as {
      productCount: number;
      advisoryCount: number;
      warnings: string[];
    };
    expect(validReport.productCount).toBe(CATALOG_PRODUCTS.length);
    expect(validReport.advisoryCount).toBe(totalChecked);
  });

  it('壊れたトークン（>= 1.0.0-nxt）を混ぜると isValidRange / validateDb の検証が失敗すること', () => {
    expect(isValidRange('>= 1.0.0-nxt')).toBe(false);
    expect(isValidRange('>= 1.0.0-nxt, < 2.0.0')).toBe(false);

    const brokenDb = structuredClone(advisoryDbJson) as Record<string, unknown>;
    delete brokenDb.integrity;
    (brokenDb.libraries as typeof advisoryDbJson.libraries).angular.versions[0].range = '>= 1.0.0-nxt, < 2.0.0';
    expect(() => validateDb(brokenDb)).toThrow(/range が version-matcher で解釈できない書式です/);
  });

  it('v1.8.0 T01: manifest の版が package.json の版と同じリリースであり、minExtensionVersion が build-db の MIN_EXTENSION_VERSION と一致すること', () => {
    // DB だけの自動リリースは manifest に 4 つ目の番号を付ける（isSameRelease が許す）
    expect(
      isSameRelease(manifestJson.version, readPackageVersion()),
      `manifest の版 ${manifestJson.version} が package.json の版 ${readPackageVersion()} と同じリリースではありません`
    ).toBe(true);
    expect(advisoryDbJson.minExtensionVersion).toBe(MIN_EXTENSION_VERSION);
  });

  it('v1.8.0 T01（旧 D17）: getAdvisoryDbMetadata() が同梱 DB のメタデータをそのまま返すこと', () => {
    const meta = getAdvisoryDbMetadata();
    const libs = advisoryDbJson.libraries as Record<string, { versions: unknown[] }>;
    const computedCount = Object.values(libs).reduce((acc, lib) => acc + lib.versions.length, 0);
    const coverage = advisoryDbJson.coverage as { totalAdvisories?: number } | undefined;

    // v1.8.1 T02: distro 節の追加で schema 2.3（H7）
    expect(['2.1', '2.2', '2.3']).toContain(meta.schemaVersion);
    expect(meta.schemaVersion).toBe(advisoryDbJson.schemaVersion);
    expect(meta.dataVersion).toBe(advisoryDbJson.dataVersion);
    expect(meta.dataVersion).toMatch(/^\d{8}$/); // YYYYMMDD形式
    expect(meta.productCount).toBe(Object.keys(libs).length);
    expect(meta.advisoryCount).toBe(coverage?.totalAdvisories ?? computedCount);
    expect(meta.sources.length).toBeGreaterThan(0);
    expect(meta.coverage.technologies.length).toBeGreaterThan(0);
    expect(['success', 'partial']).toContain(meta.syncStatus);
  });
});

describe('照合の挙動（固定 DB で確かめる）', () => {
  const fixtureDb = rawFixtureDb as unknown as AdvisoryDatabase;

  it('T05 (P1): 固定 DB で Apache 2.4.49 は該当し、Apache/2.4.41 (Ubuntu) はディストリビューション版として Needs Review のまま（上流版での参考件数あり）であること', () => {
    const apache = matchOfflineAdvisories('Apache', '2.4.49', fixtureDb);
    expect(apache.matchStatus).toBe('Potentially Affected');
    expect(apache.advisories.length).toBeGreaterThan(0);

    const ubuntuApache = matchOfflineAdvisories('Apache', 'Apache/2.4.41 (Ubuntu)', fixtureDb);
    expect(ubuntuApache.matchStatus).toBe('Needs Review');
    expect(ubuntuApache.advisories).toHaveLength(0);
    expect(ubuntuApache.upstreamAdvisoriesCount).toBeGreaterThan(0);
  });
});

/**
 * v1.8.1 T02: 同梱 DB の distro 節（総合チェック C17 の前提）。
 * DB だけの自動リリースで中身が変わっても落ちないよう、件数・日付・特定のリリースの有無は比べない。
 * OS のライフサイクル（releases）は外部データの取得の後でないと入らないので、空でもよい（取得できなかった夜は空のまま）。
 */
describe('v1.8.1 T02: 同梱 advisory-db.json の distro 節', () => {
  const db = advisoryDbJson as unknown as {
    distro?: AdvisoryDistroSection;
    libraries: unknown;
    integrity?: { digest?: string; distroDigest?: string };
  };
  const mapFile = (): DistroMapFile =>
    JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'data', 'advisories', 'distro-map.json'), 'utf-8')) as DistroMapFile;
  const sha256 = (text: string): string => crypto.createHash('sha256').update(text).digest('hex');

  it('distro 節があり、releases と map が配列であること', () => {
    expect(db.distro).toBeDefined();
    expect(Array.isArray(db.distro?.releases)).toBe(true);
    expect(Array.isArray(db.distro?.map)).toBe(true);
  });

  it('distro.map は data/advisories/distro-map.json の全項目と同じで、全項目に evidenceUrl と verifiedAt があること', () => {
    const entries = mapFile().entries;
    expect(db.distro?.map).toHaveLength(entries.length);
    for (const src of entries) {
      const found = db.distro?.map.find((e) => e.release === src.release && e.product === src.product && e.sourcePackage === src.sourcePackage);
      expect(found, `${src.release} ${src.product}`).toBeDefined();
      expect(found?.upstreamVersions).toEqual(src.upstreamVersions);
      expect(found?.evidenceUrl).toMatch(/^https:\/\//);
      expect(found?.verifiedAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it('integrity は libraries と distro の両方と一致すること（distro 節の手編集の検出）', () => {
    expect(db.integrity?.digest).toBe(sha256(JSON.stringify(db.libraries)));
    expect(db.integrity?.distroDigest).toBe(sha256(JSON.stringify(db.distro)));
  });

  it('distro.releases の各項目は catalog.json の OS の節にあるリリースで、標準・延長サポートの終了日の項目を持つこと', () => {
    const distros = (catalogJson as unknown as { distros?: Record<string, { releases?: string[] }> }).distros ?? {};
    for (const r of db.distro?.releases ?? []) {
      expect(r.release).toBe(`${r.family}:${r.cycle}`);
      expect(distros[r.family]?.releases, r.release).toContain(r.cycle);
      expect('standardSupportEnd' in r, r.release).toBe(true);
      expect('extendedSupportEnd' in r, r.release).toBe(true);
    }
  });
});
