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

    // v1.8.1 T02: distro 節の追加で schema 2.3（H7）。v1.8.2 T06: sources の構造化で schema 2.4（H10）
    expect(['2.1', '2.2', '2.3', '2.4']).toContain(meta.schemaVersion);
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

/**
 * v1.8.1 T05: 同梱 DB の distro.advisories と distro._source（H2・§5.2・C17）。
 * OSV の取得（[T05][data]）の前は advisories が空のオブジェクトでよい。件数・日付・特定の CVE の有無は比べない。
 */
describe('v1.8.1 T05: 同梱 advisory-db.json の distro.advisories と _source', () => {
  type SourceRecord = { name?: unknown; url?: unknown; ecosystem?: unknown; license?: unknown; licenseNote?: unknown; retrievedAt?: unknown; recordCount?: unknown };
  const distro = (advisoryDbJson as unknown as { distro?: { advisories?: Record<string, Record<string, Array<Record<string, unknown>>>>; _source?: SourceRecord[] } }).distro;

  it('_source に OSV（Debian・Ubuntu）と endoflife.date があり、全要素に license か licenseNote があること', () => {
    const src = distro?._source;
    expect(Array.isArray(src) && src.length > 0).toBe(true);
    for (const s of src ?? []) expect(Boolean(s.license) || Boolean(s.licenseNote), String(s.name)).toBe(true);
    expect(src?.some((s) => s.ecosystem === 'Debian')).toBe(true);
    expect(src?.some((s) => s.ecosystem === 'Ubuntu')).toBe(true);
    expect(src?.some((s) => typeof s.url === 'string' && s.url.startsWith('https://endoflife.date/'))).toBe(true);
    for (const s of src ?? []) expect(typeof s.recordCount === 'number' && s.recordCount >= 0).toBe(true);
  });

  it('advisories はオブジェクトで、キーは Debian / Ubuntu のリリースだけ（H1）、各 CVE は決めた項目だけを持つこと', () => {
    const adv = distro?.advisories;
    expect(adv !== null && typeof adv === 'object' && !Array.isArray(adv)).toBe(true);
    for (const [release, byPkg] of Object.entries(adv ?? {})) {
      expect(release).toMatch(/^(debian|ubuntu):[0-9][0-9.]*$/);
      for (const list of Object.values(byPkg)) {
        expect(Array.isArray(list)).toBe(true);
        for (const e of list) {
          for (const k of Object.keys(e)) expect(['cve', 'status', 'fixedVersions', 'esm', 'osvIds']).toContain(k);
          expect(['fixed', 'open', 'not-affected']).toContain(e.status);
        }
      }
    }
  });

  it('distro 節は 800 KB 以下であること（H8）', () => {
    expect(Buffer.byteLength(JSON.stringify(distro ?? {}))).toBeLessThanOrEqual(800 * 1024);
  });
});

/**
 * v1.8.2 T06: 同梱 DB の出典（sources）とスキーマ 2.4・サイズ（指示書 §5.3、H9・H10）。
 * 同梱 DB は実装の工程で夜のシェルが build-db（ネットワークなし）で作り直す。件数・日付は比べない。
 */
describe('v1.8.2 T06: 同梱 advisory-db.json の sources（スキーマ 2.4）', () => {
  type TopSource = { name?: unknown; url?: unknown; ecosystem?: unknown; license?: unknown; licenseNote?: unknown; retrievedAt?: unknown; recordCount?: unknown };
  const db = advisoryDbJson as unknown as { schemaVersion: string; sources?: unknown[]; distro?: { _source?: TopSource[] } };
  const DB_FILE = path.join(REPO_ROOT, 'src', 'detection', 'advisory-db.json');

  it('schemaVersion が 2.4 であること', () => {
    expect(db.schemaVersion).toBe('2.4');
  });

  it('sources はすべてオブジェクトで、name・url（https）・license か licenseNote・retrievedAt・recordCount を持つこと', () => {
    expect(Array.isArray(db.sources) && db.sources.length > 0).toBe(true);
    for (const raw of db.sources ?? []) {
      expect(typeof raw === 'object' && raw !== null, `文字列のままの出典: ${String(raw)}`).toBe(true);
      const s = raw as TopSource;
      expect(typeof s.name === 'string' && s.name.length > 0).toBe(true);
      expect(typeof s.url === 'string' && s.url.startsWith('https://'), String(s.name)).toBe(true);
      expect('license' in s, String(s.name)).toBe(true);
      expect(Boolean(s.license) || Boolean(s.licenseNote), `license も licenseNote も無い: ${String(s.name)}`).toBe(true);
      expect(s.retrievedAt === null || (typeof s.retrievedAt === 'string' && !Number.isNaN(Date.parse(s.retrievedAt))), String(s.name)).toBe(true);
      expect(Number.isInteger(s.recordCount) && (s.recordCount as number) >= 0, String(s.name)).toBe(true);
    }
  });

  it('Debian の出典は license: null と licenseNote「ライセンスの明記なし（出典のみ表示）」、Ubuntu は CC-BY-SA-4.0 であること', () => {
    const srcs = (db.sources ?? []) as TopSource[];
    const deb = srcs.filter((s) => s.ecosystem === 'Debian');
    const ubu = srcs.filter((s) => s.ecosystem === 'Ubuntu');
    expect(deb).toHaveLength(1);
    expect(ubu).toHaveLength(1);
    expect(deb[0].license).toBeNull();
    expect(deb[0].licenseNote).toBe('ライセンスの明記なし（出典のみ表示）');
    expect(ubu[0].license).toBe('CC-BY-SA-4.0');
  });

  it('同梱 DB は validateDb を通ること（スキーマ 2.4 の検査を含む）', () => {
    expect(() => validateDb(advisoryDbJson, { sizeBytes: fs.statSync(DB_FILE).size })).not.toThrow();
  });

  it('同梱 DB のファイルサイズが上限（check-size の advisoryDb）以下で、distro 節も上限以下であること', async () => {
    // @ts-expect-error scripts/ci/check-size.mjs は型定義を持たない .mjs モジュール
    const mod = (await import('../scripts/ci/check-size.mjs')) as { SIZE_LIMITS: { advisoryDb: number; distro: number } };
    expect(fs.statSync(DB_FILE).size).toBeLessThanOrEqual(mod.SIZE_LIMITS.advisoryDb);
    expect(Buffer.byteLength(JSON.stringify(db.distro ?? {}))).toBeLessThanOrEqual(mod.SIZE_LIMITS.distro);
  });

  it('getAdvisoryDbMetadata() の sources は従来どおり文字列（出典の名前）の配列で、sourceRecords に構造化した出典が入ること（互換）', () => {
    type Meta = ReturnType<typeof getAdvisoryDbMetadata> & { sourceRecords?: Array<{ name: string; license: string | null; licenseNote?: string }> };
    const meta = getAdvisoryDbMetadata() as Meta;
    const names = ((db.sources ?? []) as TopSource[]).map((s) => s.name);
    expect(meta.sources.every((s) => typeof s === 'string')).toBe(true);
    expect(meta.sources).toEqual(names);
    expect(Array.isArray(meta.sourceRecords)).toBe(true);
    expect(meta.sourceRecords?.map((s) => s.name)).toEqual(names);
    for (const s of meta.sourceRecords ?? []) expect(Boolean(s.license) || Boolean(s.licenseNote), s.name).toBe(true);
  });
});

/**
 * v1.8.2 T07: 同梱 DB の出典が THIRD_PARTY_NOTICES.md と拡張機能内の出典の一覧にすべて載っていること（指示書 §5.4、§7 C22）。
 * 件数・日付は比べない。照合は名前と URL だけ。
 */
describe('v1.8.2 T07: 同梱 DB の出典と THIRD_PARTY_NOTICES.md・出典の一覧の一致', () => {
  type Src = { name?: unknown; url?: unknown };
  const db = advisoryDbJson as unknown as { sources?: Src[]; distro?: { _source?: Src[] } };
  const NOTICES_FILE = path.join(REPO_ROOT, 'THIRD_PARTY_NOTICES.md');
  const allDbSources = (): Src[] => [...(db.sources ?? []), ...(db.distro?._source ?? [])];

  it('CI のチェック（check-data-sources）が、同梱 DB と THIRD_PARTY_NOTICES.md で合格し、照合を飛ばさないこと', async () => {
    // @ts-expect-error scripts/ci/check-data-sources.mjs は型定義を持たない .mjs モジュール
    const mod = (await import('../scripts/ci/check-data-sources.mjs')) as {
      checkDataSources: (i: { db: unknown; noticesText: string | null }) => { ok: boolean; issues: string[]; warnings: string[] };
    };
    expect(fs.existsSync(NOTICES_FILE)).toBe(true);
    const res = mod.checkDataSources({ db: advisoryDbJson, noticesText: fs.readFileSync(NOTICES_FILE, 'utf-8') });
    expect(res.issues).toEqual([]);
    expect(res.ok).toBe(true);
    expect(res.warnings.join('\n')).not.toContain('スキップ');
  });

  it('同梱 DB の出典（sources と distro._source）の名前と URL が、どちらも THIRD_PARTY_NOTICES.md にあること', () => {
    expect(fs.existsSync(NOTICES_FILE)).toBe(true);
    const text = fs.readFileSync(NOTICES_FILE, 'utf-8');
    for (const s of allDbSources()) {
      expect(text, String(s.name)).toContain(String(s.name));
      expect(text, String(s.name)).toContain(String(s.url));
    }
  });

  it('同梱 DB の出典は、拡張機能内の出典の一覧（BUNDLED_DATA_SOURCES）に同じ名前と URL で入っていること', async () => {
    const { BUNDLED_DATA_SOURCES } = await import('../src/shared/data-sources');
    for (const s of allDbSources()) {
      const hit = BUNDLED_DATA_SOURCES.find((b: { name: string; url: string }) => b.url === s.url);
      expect(hit, `出典の一覧に無い: ${String(s.name)}`).toBeDefined();
      expect(hit!.name).toBe(s.name);
    }
  });
});
