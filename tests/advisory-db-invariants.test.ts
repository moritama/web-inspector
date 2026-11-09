import { describe, it, expect } from 'vitest';
// @ts-expect-error scripts/validate-advisories.mjs は型定義を持たない .mjs モジュール
import { isValidRange, validateDb } from '../scripts/validate-advisories.mjs';
import advisoryDbJson from '../src/detection/advisory-db.json';
import manifestJson from '../public/manifest.json';
import { AdvisoryDatabase, matchOfflineAdvisories } from '../src/detection/advisory';
import { compareVersions } from '../src/security/version-matcher';

const EXPECTED_PRODUCTS = [
  'jquery',
  'bootstrap',
  'react',
  'vue',
  'angular',
  'angularjs',
  'lodash',
  'moment',
  'wordpress',
  'php',
  'nginx',
  'apache',
  'laravel',
  'nodejs',
];

describe('同梱 advisory-db.json の不変条件 (Invariants)', () => {
  it('schemaVersion が 2.2 であり、基本メタデータが揃っていること', () => {
    expect(advisoryDbJson.schemaVersion).toBe('2.2');
    expect(advisoryDbJson.dataVersion).toMatch(/^\d{8}$/);
    expect(typeof advisoryDbJson.generatedAt).toBe('string');
    expect(Number.isNaN(Date.parse(advisoryDbJson.generatedAt))).toBe(false);
  });

  it('全 14 製品が libraries に存在し、それぞれ aliases / versions / eol を持つこと', () => {
    const productKeys = Object.keys(advisoryDbJson.libraries).sort();
    expect(productKeys).toEqual([...EXPECTED_PRODUCTS].sort());

    for (const key of EXPECTED_PRODUCTS) {
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
    expect(validReport.productCount).toBe(EXPECTED_PRODUCTS.length);
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

  it('T05 (P1): NVD 自動取り込みが有効化され、minExtensionVersion が 1.7.0 であり、Apache 2.4.52 で CVE-2023-25690 が該当し、Apache/2.4.41 (Ubuntu) は Needs Review のままであること', () => {
    expect(advisoryDbJson.minExtensionVersion).toBe('1.7.0');
    // DB だけの自動リリースは manifest に 4 つ目の番号を付ける（例: 1.7.1.1）
    expect(manifestJson.version).toMatch(/^1\.7\.1(\.\d+)?$/);

    // C04c（エントリ半減テスト）で間引かれていない本物の DB では収録件数が 400 件前後（350 件以上）であり、CVE-2023-25690 が確実に含まれること
    const isUnmodifiedApache =
      advisoryDbJson.libraries.apache.versions.length === advisoryDbJson.coverage.byProduct.apache.count;
    if (isUnmodifiedApache) {
      expect(advisoryDbJson.coverage.totalAdvisories).toBeGreaterThanOrEqual(350);
    }

    const realDb = advisoryDbJson as unknown as AdvisoryDatabase;
    const apache2452 = matchOfflineAdvisories('Apache', '2.4.52', realDb);
    expect(apache2452.matchStatus).toBe('Potentially Affected');
    expect(apache2452.advisories.length).toBeGreaterThan(0);

    if (isUnmodifiedApache) {
      expect(apache2452.advisories.map((a) => a.id)).toContain('CVE-2023-25690');
    }

    const ubuntuApache = matchOfflineAdvisories('Apache', 'Apache/2.4.41 (Ubuntu)', realDb);
    expect(ubuntuApache.matchStatus).toBe('Needs Review');
    expect(ubuntuApache.advisories).toHaveLength(0);
    expect(ubuntuApache.upstreamAdvisoriesCount).toBeGreaterThan(0);
  });
});
