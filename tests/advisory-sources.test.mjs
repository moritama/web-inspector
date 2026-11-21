/**
 * v1.8.2 T06: 同梱データの出典（データと生成、E。指示書 §5.2・§5.3、H9・H10）
 *
 * 受け入れ条件
 *   1. すべての出典に license か licenseNote がある（build-db の出力・validateDb・CI のチェック）
 *   2. スキーマ 2.4（advisory-db.json の sources が distro._source と同じ形のオブジェクトの配列）
 *   3. 古いスキーマ（sources が文字列の配列）を読む側が壊れない（validateDb。拡張機能側は tests/advisory-sources-compat.test.ts）
 *   4. サイズの上限内（同梱 DB は tests/advisory-db-invariants.test.ts）
 *   5. PSL の生成ファイルの先頭に MPL 2.0 の表示と元のファイルの URL
 *
 * - ネットワークには出ない。入力は合成の上流スナップショット（tests/fixtures/advisory-upstream.mjs）。
 * - DB の版・件数・日付・dataVersion は直接書かない。件数は生成した DB から数えて比べる。
 * - 出典の見分けは指示書 §5.2 の表の値（URL のホスト・ライセンス・ecosystem）で行い、表示名の一字一句には依存しない。
 *   Debian の licenseNote だけは指示書 §5.3 が文字列を指定しているので、その文字列で確かめる。
 * - 一時ディレクトリは os.tmpdir() に作り、fs.realpathSync で解決したパスを使う。
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { buildDatabase, OUTPUT_SCHEMA_VERSION } from '../scripts/advisories/build-db.mjs';
import { PSL_UPSTREAM_URL, renderPslGeneratedTs, writeGeneratedPslModule } from '../scripts/advisories/lib/psl.mjs';
import { validateDb } from '../scripts/validate-advisories.mjs';
import { bumpAdvisoryDb } from '../scripts/ci/rehearse-db-release.mjs';
import { fixtureCatalog, fixtureCurated, fixtureUpstream } from './fixtures/advisory-upstream.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHECK_SCRIPT = path.join(REPO_ROOT, 'scripts', 'ci', 'check-data-sources.mjs');
const CI_YML_PATH = path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml');
const PSL_GENERATED_PATH = path.join(REPO_ROOT, 'src', 'security', 'psl-rules.generated.ts');
const PSL_FIXTURE_PATH = path.join(REPO_ROOT, 'tests', 'fixtures', 'psl.fixture.dat');

// validateDb は未来の generatedAt を拒否するので、合成の上流スナップショットの取得日時に合わせる
const GENERATED_AT = fixtureUpstream.manifest.fetchedAt;
const AS_OF = GENERATED_AT.slice(0, 10);
/** 指示書 §5.3 が指定する Debian の licenseNote */
const DEBIAN_LICENSE_NOTE = 'ライセンスの明記なし（出典のみ表示）';

const tempDirs = [];
const mkTemp = (prefix) => {
  // macOS の /tmp はシンボリックリンクなので、解決したパスを使う
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
};
afterEach(() => {
  while (tempDirs.length > 0) fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 合成の入力
// ---------------------------------------------------------------------------

/** distro 節を作るための catalog（出典の定義 distroSources は合成。本番の catalog.json の値には依存しない） */
const distroCatalog = {
  ...fixtureCatalog,
  distros: {
    ubuntu: { name: 'Ubuntu', eol: { slug: 'ubuntu' }, releases: ['20.04'] },
    debian: { name: 'Debian', eol: { slug: 'debian' }, releases: ['12'] },
  },
  distroSources: [
    { name: 'OSV.dev (Debian Security Tracker)', url: 'https://osv.dev/list?ecosystem=Debian', ecosystem: 'Debian', license: null, licenseNote: '合成: 出典の定義' },
    { name: 'OSV.dev (Ubuntu Security Notices)', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0' },
    { name: 'endoflife.date', url: 'https://endoflife.date/', ecosystem: null, license: 'MIT' },
  ],
};

/** fetch-upstream が保存する OS のライフサイクルの形（upstream/distro-eol/<slug>.json）。値は合成 */
const distroEol = {
  ubuntu: {
    slug: 'ubuntu',
    fetchedAt: GENERATED_AT,
    cycles: [{ cycle: '20.04', codename: 'Focal Fossa', releaseDate: '2090-04-01', eol: '2095-05-31', support: '2092-10-01', extendedSupport: '2100-04-23', lts: true, latest: '20.04.6' }],
  },
  debian: {
    slug: 'debian',
    fetchedAt: GENERATED_AT,
    cycles: [{ cycle: '12', codename: 'Bookworm', releaseDate: '2090-06-10', eol: '2098-06-30', support: '2096-07-11', extendedSupport: false, lts: false, latest: '12.15' }],
  },
};

const mapEntry = (o) => ({ codename: null, verifiedAt: '2090-01-15', evidenceUrl: 'https://launchpad.net/ubuntu/+source/nginx/+publishinghistory', ...o });
const distroMap = {
  schemaVersion: 1,
  entries: [
    mapEntry({ family: 'ubuntu', release: 'ubuntu:20.04', codename: 'focal', product: 'nginx', upstreamVersions: ['1.18.0'], sourcePackage: 'nginx' }),
    mapEntry({ family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'nginx', upstreamVersions: ['1.22.1'], sourcePackage: 'nginx', evidenceUrl: 'https://tracker.debian.org/pkg/nginx' }),
  ],
};

/** 上流のスナップショットが 1 つも無い状態 */
const EMPTY_UPSTREAM = { manifest: null, osv: {}, osvDistro: {}, nvd: {}, eol: {}, distroEol: {}, kev: null, nvdScores: {} };

const buildPlain = (upstream = fixtureUpstream) =>
  buildDatabase({ catalog: fixtureCatalog, curated: fixtureCurated, upstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT });

const buildDistro = () =>
  buildDatabase({
    catalog: distroCatalog,
    curated: fixtureCurated,
    upstream: { ...fixtureUpstream, distroEol },
    previousDb: null,
    asOf: AS_OF,
    generatedAt: GENERATED_AT,
    distroMap,
  });

/** validateDb の最低製品数を満たすための合成の製品（tests/advisory-distro-pipeline.test.mjs と同じ考え方） */
function padProducts() {
  const out = {};
  for (let i = 0; i < 3; i++) {
    out[`dummy${i}`] = {
      aliases: [`dummy${i}`],
      eol: [],
      versions: Array.from({ length: 4 }, (_, j) => ({
        range: '< 1.0.0',
        cve: `CVE-2099-9${i}0${j}`,
        cvssScore: 5,
        severity: 'medium',
        title: 'dummy',
        fixedVersion: '1.0.0',
        fixStatus: 'fixed',
        advisoryUrl: `https://nvd.nist.gov/vuln/detail/CVE-2099-9${i}0${j}`,
        verifiedAt: '2090-01-01',
        scoreSource: 'test',
        origin: 'curated',
      })),
    };
  }
  return out;
}

/** integrity を付け直した、validateDb に通せる DB */
function padded(db) {
  const out = structuredClone(db);
  out.libraries = { ...out.libraries, ...padProducts() };
  return bumpAdvisoryDb(out);
}

// --- 出典の見分け（指示書 §5.2 の表の値で見る） ---
const hostOf = (s) => {
  try {
    return new URL(s.url).hostname;
  } catch {
    return '';
  }
};
const findNvd = (srcs) => srcs.filter((s) => hostOf(s) === 'nvd.nist.gov');
const findGhsa = (srcs) => srcs.filter((s) => s.license === 'CC-BY-4.0');
const findUbuntu = (srcs) => srcs.filter((s) => s.ecosystem === 'Ubuntu');
const findDebian = (srcs) => srcs.filter((s) => s.ecosystem === 'Debian');
const findEol = (srcs) => srcs.filter((s) => hostOf(s) === 'endoflife.date');
const findKev = (srcs) => srcs.filter((s) => s.license === 'CC0-1.0');

const allVersions = (db) => Object.values(db.libraries).flatMap((lib) => (Array.isArray(lib.versions) ? lib.versions : []));
const hasSource = (v, key) => Array.isArray(v.sources) && v.sources.includes(key);

/** 出典の 1 要素が distro._source と同じ形か（name・url・ecosystem・license・licenseNote?・retrievedAt・recordCount） */
function expectSourceShape(s) {
  expect(s !== null && typeof s === 'object' && !Array.isArray(s), `出典がオブジェクトではありません: ${JSON.stringify(s)}`).toBe(true);
  expect(typeof s.name === 'string' && s.name.length > 0, `name: ${JSON.stringify(s)}`).toBe(true);
  expect(typeof s.url === 'string' && s.url.startsWith('https://'), `url: ${JSON.stringify(s)}`).toBe(true);
  expect('ecosystem' in s, `ecosystem が無い: ${s.name}`).toBe(true);
  expect(s.ecosystem === null || typeof s.ecosystem === 'string', `ecosystem: ${s.name}`).toBe(true);
  expect('license' in s, `license が無い: ${s.name}`).toBe(true);
  expect(s.license === null || (typeof s.license === 'string' && s.license.length > 0), `license: ${s.name}`).toBe(true);
  if ('licenseNote' in s) expect(typeof s.licenseNote === 'string' && s.licenseNote.length > 0, `licenseNote: ${s.name}`).toBe(true);
  expect(Boolean(s.license) || Boolean(s.licenseNote), `license も licenseNote も無い: ${s.name}`).toBe(true);
  expect('retrievedAt' in s, `retrievedAt が無い: ${s.name}`).toBe(true);
  expect(s.retrievedAt === null || (typeof s.retrievedAt === 'string' && !Number.isNaN(Date.parse(s.retrievedAt))), `retrievedAt: ${s.name}`).toBe(true);
  expect(Number.isInteger(s.recordCount) && s.recordCount >= 0, `recordCount: ${s.name}`).toBe(true);
}

// ---------------------------------------------------------------------------
// 受け入れ条件 2: スキーマ 2.4
// ---------------------------------------------------------------------------

describe('T06: スキーマ 2.4（H10・§5.3）', () => {
  it('build-db の出力スキーマは 2.4 で、生成した DB の schemaVersion もそうであること', () => {
    expect(OUTPUT_SCHEMA_VERSION).toBe('2.4');
    expect(buildPlain().db.schemaVersion).toBe(OUTPUT_SCHEMA_VERSION);
    expect(buildDistro().db.schemaVersion).toBe(OUTPUT_SCHEMA_VERSION);
  });

  it('sources は文字列ではなく、distro._source と同じ形のオブジェクトの配列であること（distro 節あり・なしの両方）', () => {
    for (const { db } of [buildPlain(), buildDistro()]) {
      expect(Array.isArray(db.sources) && db.sources.length > 0).toBe(true);
      expect(db.sources.some((s) => typeof s === 'string'), '文字列のままの出典があります').toBe(false);
      for (const s of db.sources) expectSourceShape(s);
    }
  });

  it('同じ入力から同じ sources ができること（決定的）。同じ URL の出典が重複しないこと', () => {
    const a = buildDistro().db.sources;
    const b = buildDistro().db.sources;
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    const urls = a.map((s) => s.url);
    expect(new Set(urls).size).toBe(urls.length);
  });
});

// ---------------------------------------------------------------------------
// 受け入れ条件 1: すべての出典に license か licenseNote（§5.2 の表）
// ---------------------------------------------------------------------------

describe('T06: 出典とライセンス（H9・§5.2）', () => {
  it('distro 節があるとき、NVD・GitHub Advisory Database・Ubuntu・Debian・endoflife.date・CISA KEV がちょうど 1 つずつあること', () => {
    const srcs = buildDistro().db.sources;
    expect(findNvd(srcs)).toHaveLength(1);
    expect(findGhsa(srcs)).toHaveLength(1);
    expect(findUbuntu(srcs)).toHaveLength(1);
    expect(findDebian(srcs)).toHaveLength(1);
    expect(findEol(srcs)).toHaveLength(1);
    expect(findKev(srcs)).toHaveLength(1);
  });

  it('ライセンスが §5.2 の表のとおりであること（GHSA は CC-BY-4.0、Ubuntu は CC-BY-SA-4.0、endoflife.date は MIT、CISA KEV は CC0-1.0）', () => {
    const srcs = buildDistro().db.sources;
    expect(findUbuntu(srcs)[0].license).toBe('CC-BY-SA-4.0');
    expect(findEol(srcs)[0].license).toBe('MIT');
    // 見分けに使ったライセンスの値が、それぞれ想定の出典に付いていること
    expect(findGhsa(srcs)[0].url).toMatch(/advisory-database|osv\.dev/);
    expect(findKev(srcs)[0].url).toMatch(/cisagov|cisa\.gov/);
  });

  it('Debian は license: null と licenseNote「ライセンスの明記なし（出典のみ表示）」であること（§5.3）', () => {
    const deb = findDebian(buildDistro().db.sources)[0];
    expect(deb.license).toBeNull();
    expect(deb.licenseNote).toBe(DEBIAN_LICENSE_NOTE);
  });

  it('NVD は license が無い（米国政府の公有データ）ので license: null と licenseNote を持つこと', () => {
    const nvd = findNvd(buildDistro().db.sources)[0];
    expect(nvd.license).toBeNull();
    expect(typeof nvd.licenseNote === 'string' && nvd.licenseNote.length > 0).toBe(true);
  });

  it('陰性: distro 節が無いときは Ubuntu と Debian の出典を出さず、他の 4 つは出すこと', () => {
    const { db } = buildPlain();
    expect(db.distro).toBeUndefined();
    expect(findUbuntu(db.sources)).toHaveLength(0);
    expect(findDebian(db.sources)).toHaveLength(0);
    expect(findNvd(db.sources)).toHaveLength(1);
    expect(findGhsa(db.sources)).toHaveLength(1);
    expect(findEol(db.sources)).toHaveLength(1);
    expect(findKev(db.sources)).toHaveLength(1);
  });

  it('陰性: 自作の curated.json と、DB に入らない PSL・Launchpad・sources.debian.org は出典に入れないこと（§5.2 の表の外）', () => {
    const srcs = buildDistro().db.sources;
    for (const s of srcs) {
      expect(/curated/i.test(`${s.name} ${s.url}`), `curated: ${s.name}`).toBe(false);
      expect(['publicsuffix.org', 'launchpad.net', 'api.launchpad.net', 'sources.debian.org']).not.toContain(hostOf(s));
    }
  });
});

// ---------------------------------------------------------------------------
// retrievedAt・recordCount（distro._source と同じ意味: 取得日時と、DB に入った件数）
// ---------------------------------------------------------------------------

describe('T06: 出典の retrievedAt と recordCount', () => {
  it('Ubuntu と Debian の retrievedAt・recordCount は distro._source の同じ系統の要素と一致すること', () => {
    const { db } = buildDistro();
    for (const eco of ['Ubuntu', 'Debian']) {
      const top = db.sources.find((s) => s.ecosystem === eco);
      const inner = db.distro._source.find((s) => s.ecosystem === eco);
      expect(top.retrievedAt).toBe(inner.retrievedAt);
      expect(top.recordCount).toBe(inner.recordCount);
    }
  });

  it('GHSA・NVD・CISA KEV の recordCount は、DB の libraries のうちその出典に由来する件数であること', () => {
    for (const { db } of [buildPlain(), buildDistro()]) {
      const vers = allVersions(db);
      expect(findGhsa(db.sources)[0].recordCount).toBe(vers.filter((v) => hasSource(v, 'osv')).length);
      expect(findNvd(db.sources)[0].recordCount).toBe(vers.filter((v) => hasSource(v, 'nvd')).length);
      expect(findKev(db.sources)[0].recordCount).toBe(vers.filter((v) => v.kev === true).length);
    }
    // 合成の入力には OSV・NVD・KEV の由来がそれぞれ 1 件以上ある（0 どうしの一致で通らないことの確認）
    const vers = allVersions(buildPlain().db);
    expect(vers.some((v) => hasSource(v, 'osv'))).toBe(true);
    expect(vers.some((v) => hasSource(v, 'nvd'))).toBe(true);
    expect(vers.some((v) => v.kev === true)).toBe(true);
  });

  it('endoflife.date の recordCount は、endoflife.date 由来の製品の EOL サイクル数と（distro 節があれば）distro._source の endoflife.date の件数の和であること', () => {
    for (const build of [buildPlain, buildDistro]) {
      const { db, report } = build();
      const libCycles = Object.entries(db.libraries)
        .filter(([k]) => report.products[k]?.eolSource === 'endoflife.date')
        .reduce((n, [, lib]) => n + lib.eol.length, 0);
      const distroEolCount = db.distro ? db.distro._source.find((s) => s.ecosystem === null).recordCount : 0;
      expect(libCycles).toBeGreaterThan(0);
      expect(findEol(db.sources)[0].recordCount).toBe(libCycles + distroEolCount);
    }
  });

  it('上流のスナップショットがあれば retrievedAt はその取得日時（ISO 8601）であること（GHSA・NVD・endoflife.date）', () => {
    const srcs = buildPlain().db.sources;
    for (const s of [findGhsa(srcs)[0], findNvd(srcs)[0], findEol(srcs)[0]]) expect(s.retrievedAt, s.name).toBe(GENERATED_AT);
  });

  it('同じ出典のスナップショットが複数あるときは、いちばん新しい取得日時を retrievedAt にすること（複数の場合）', () => {
    const older = new Date(Date.parse(GENERATED_AT) - 3 * 86400_000).toISOString();
    const upstream = structuredClone(fixtureUpstream);
    upstream.nvd['f5:nginx'].fetchedAt = older;
    upstream.osv['npm:lodash'].fetchedAt = older;
    upstream.eol.react.fetchedAt = older;
    const srcs = buildPlain(upstream).db.sources;
    expect(findNvd(srcs)[0].retrievedAt).toBe(GENERATED_AT);
    expect(findGhsa(srcs)[0].retrievedAt).toBe(GENERATED_AT);
    expect(findEol(srcs)[0].retrievedAt).toBe(GENERATED_AT);

    // すべて古ければ古い日時になる（単一の場合）
    const allOld = structuredClone(upstream);
    for (const snap of Object.values(allOld.osv)) snap.fetchedAt = older;
    expect(findGhsa(buildPlain(allOld).db.sources)[0].retrievedAt).toBe(older);
  });

  it('CISA KEV の retrievedAt は manifest の kev の取得日時であること（無ければ null）', () => {
    const upstream = structuredClone(fixtureUpstream);
    upstream.manifest.sources = { ...upstream.manifest.sources, kev: { status: 'ok', count: 1, fetchedAt: GENERATED_AT } };
    expect(findKev(buildPlain(upstream).db.sources)[0].retrievedAt).toBe(GENERATED_AT);
    const none = findKev(buildPlain(EMPTY_UPSTREAM).db.sources)[0].retrievedAt;
    expect(none).toBeNull();
  });

  it('陰性: 上流のスナップショットが 1 つも無いときも出典は出し、retrievedAt は null、recordCount は 0 であること（日時や件数を作らない）', () => {
    const { db } = buildPlain(EMPTY_UPSTREAM);
    for (const pick of [findNvd, findGhsa, findEol, findKev]) {
      const [s] = pick(db.sources);
      expect(s, '出典が無い').toBeDefined();
      expectSourceShape(s);
      expect(s.retrievedAt, s.name).toBeNull();
      expect(s.recordCount, s.name).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// validateDb（受け入れ条件 1・3）
// ---------------------------------------------------------------------------

describe('T06: validateDb が sources を検査する', () => {
  it('build-db の出力（schema 2.4、distro 節あり・なし）は validateDb を通ること（陽性）', () => {
    expect(() => validateDb(padded(buildPlain().db))).not.toThrow();
    expect(() => validateDb(padded(buildDistro().db))).not.toThrow();
  });

  it('古いスキーマ（2.3・2.2）で sources が文字列の配列の DB は、これまでどおり通ること（互換）', () => {
    const base = padded(buildPlain().db);
    const names = base.sources.map((s) => s.name);
    expect(() => validateDb({ ...base, schemaVersion: '2.3', sources: names })).not.toThrow();
    expect(() => validateDb({ ...base, schemaVersion: '2.2', sources: names })).not.toThrow();
  });

  it.each([
    ['文字列のままの出典がある', (db) => db.sources.push('NIST NVD 2.0 API')],
    ['license も licenseNote も無い出典がある', (db) => { db.sources[0].license = null; delete db.sources[0].licenseNote; }],
    ['license が空文字で licenseNote も無い', (db) => { db.sources[0].license = ''; delete db.sources[0].licenseNote; }],
    ['url が https でない', (db) => (db.sources[0].url = 'http://example.test/')],
    ['name が無い', (db) => delete db.sources[0].name],
    ['recordCount が負の数', (db) => (db.sources[0].recordCount = -1)],
    ['retrievedAt が日時でない', (db) => (db.sources[0].retrievedAt = 'not-a-date')],
    ['sources が空', (db) => (db.sources = [])],
  ])('陰性: schema 2.4 で %s なら拒否すること', (_label, mutate) => {
    const db = padded(buildDistro().db);
    expect(db.schemaVersion).toBe(OUTPUT_SCHEMA_VERSION);
    mutate(db);
    expect(() => validateDb(db)).toThrow();
  });

  it.each([
    ['origin が不正', (db) => (db.libraries.dummy0.versions[0].origin = 'bogus')],
    ['fixStatus が不正', (db) => (db.libraries.dummy0.versions[0].fixStatus = 'bogus')],
    ['eol.eolDate が YYYY-MM-DD でない', (db) => (db.libraries.dummy0.eol = [{ cycle: '1', eolDate: '2090/01/01', status: 'EOL' }])],
  ])('陰性: schema 2.4 でも 2.2・2.3 と同じ厳格な検査をすること（%s なら拒否）', (_label, mutate) => {
    const db = padded(buildPlain().db);
    mutate(db);
    expect(() => validateDb({ ...db, integrity: undefined })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// CI のチェック（scripts/ci/check-data-sources.mjs。§5.3「CI：すべての出典に license か licenseNote がある。
// THIRD_PARTY_NOTICES.md に DB の出典がすべて載っている」）
// ---------------------------------------------------------------------------

async function loadCheck() {
  expect(fs.existsSync(CHECK_SCRIPT), 'scripts/ci/check-data-sources.mjs がありません').toBe(true);
  const mod = await import(/* @vite-ignore */ CHECK_SCRIPT);
  expect(typeof mod.checkDataSources, 'checkDataSources が export されていません').toBe('function');
  return mod;
}

/** すべての出典の名前と URL を載せた NOTICES の本文（合成） */
const noticesFor = (db) => ['# Third-party notices', ...db.sources.map((s) => `- ${s.name} (${s.url})`)].join('\n');

describe('T06: CI のチェック check-data-sources', () => {
  it('build-db の出力と、全出典を載せた NOTICES なら合格すること（陽性）', async () => {
    const { checkDataSources } = await loadCheck();
    const { db } = buildDistro();
    const r = checkDataSources({ db, noticesText: noticesFor(db) });
    expect(r.ok, JSON.stringify(r.issues)).toBe(true);
    expect(r.issues).toEqual([]);
  });

  it.each([
    ['license も licenseNote も無い出典', (db) => { db.sources[1].license = null; delete db.sources[1].licenseNote; }],
    ['文字列のままの出典（古いスキーマの形）', (db) => (db.sources = db.sources.map((s) => s.name))],
    ['sources が無い', (db) => delete db.sources],
    ['distro._source に license も licenseNote も無い要素', (db) => { db.distro._source[0].license = null; delete db.distro._source[0].licenseNote; }],
  ])('陰性: %s があれば不合格にすること', async (_label, mutate) => {
    const { checkDataSources } = await loadCheck();
    const { db } = buildDistro();
    const notices = noticesFor(db);
    const bad = structuredClone(db);
    mutate(bad);
    const r = checkDataSources({ db: bad, noticesText: notices });
    expect(r.ok).toBe(false);
    expect(r.issues.length).toBeGreaterThan(0);
  });

  it('陰性: THIRD_PARTY_NOTICES.md に名前も URL も無い出典があれば不合格にし、その出典が分かること', async () => {
    const { checkDataSources } = await loadCheck();
    const { db } = buildDistro();
    const kev = findKev(db.sources)[0];
    const notices = db.sources
      .filter((s) => s !== kev)
      .map((s) => `- ${s.name} (${s.url})`)
      .join('\n');
    const r = checkDataSources({ db, noticesText: notices });
    expect(r.ok).toBe(false);
    expect(r.issues.join('\n')).toContain(kev.name);
  });

  it('名前か URL のどちらかが NOTICES にあれば載っているとみなすこと（表記の揺れで落とさない）', async () => {
    const { checkDataSources } = await loadCheck();
    const { db } = buildDistro();
    const byUrl = db.sources.map((s) => `- ${s.url}`).join('\n');
    const byName = db.sources.map((s) => `- ${s.name}`).join('\n');
    expect(checkDataSources({ db, noticesText: byUrl }).ok).toBe(true);
    expect(checkDataSources({ db, noticesText: byName }).ok).toBe(true);
  });

  it('NOTICES が無い（null）ときは、NOTICES の照合だけを飛ばして警告にし、license の検査はすること', async () => {
    const { checkDataSources } = await loadCheck();
    const { db } = buildDistro();
    const r = checkDataSources({ db, noticesText: null });
    expect(r.ok).toBe(true);
    expect(Array.isArray(r.warnings) && r.warnings.length > 0).toBe(true);
    const bad = structuredClone(db);
    bad.sources[0].license = null;
    delete bad.sources[0].licenseNote;
    expect(checkDataSources({ db: bad, noticesText: null }).ok).toBe(false);
  });

  it('CLI: --db と --notices を受け取り、合格なら終了コード 0、不合格なら 0 以外であること', async () => {
    await loadCheck();
    const dir = mkTemp('wi-t06-sources-');
    const { db } = buildDistro();
    const dbPath = path.join(dir, 'db.json');
    const noticesPath = path.join(dir, 'NOTICES.md');
    fs.writeFileSync(dbPath, JSON.stringify(db));
    fs.writeFileSync(noticesPath, noticesFor(db));
    const run = (args) => spawnSync(process.execPath, [CHECK_SCRIPT, ...args], { cwd: dir, encoding: 'utf-8' });

    expect(run(['--db', dbPath, '--notices', noticesPath]).status).toBe(0);

    const bad = structuredClone(db);
    findDebian(bad.sources)[0].licenseNote = undefined;
    delete findDebian(bad.sources)[0].licenseNote;
    const badPath = path.join(dir, 'bad.json');
    fs.writeFileSync(badPath, JSON.stringify(bad));
    expect(run(['--db', badPath, '--notices', noticesPath]).status).not.toBe(0);

    fs.writeFileSync(noticesPath, '# empty\n');
    expect(run(['--db', dbPath, '--notices', noticesPath]).status).not.toBe(0);

    // NOTICES のファイルが無いときは警告だけで合格（T07 で作る前に CI を止めない）
    const missing = run(['--db', dbPath, '--notices', path.join(dir, 'no-such-file.md')]);
    expect(missing.status).toBe(0);
    expect(`${missing.stdout}${missing.stderr}`).toMatch(/THIRD_PARTY_NOTICES|NOTICES/);
  });

  it('CI（.github/workflows/ci.yml）でチェックを実行すること', () => {
    const yml = fs.readFileSync(CI_YML_PATH, 'utf-8');
    expect(yml).toMatch(/run:\s*node scripts\/ci\/check-data-sources\.mjs/);
  });
});

// ---------------------------------------------------------------------------
// 受け入れ条件 5: PSL の生成ファイルの先頭に MPL 2.0 の表示と元のファイルの URL（§5.3）
// ---------------------------------------------------------------------------

/** 生成ファイルの先頭（最初の export より前） */
const headOf = (text) => {
  const i = text.indexOf('\nexport ');
  return i >= 0 ? text.slice(0, i) : text;
};

function expectMplHeader(text) {
  const head = headOf(text);
  expect(head).toContain('Mozilla Public License');
  expect(head).toMatch(/v\.\s*2\.0|2\.0/);
  expect(head).toContain('https://mozilla.org/MPL/2.0/');
  expect(head).toContain(PSL_UPSTREAM_URL);
}

describe('T06: PSL の生成ファイルの MPL 2.0 の表示', () => {
  const rules = { source: 'snapshot', suffixes: ['co.jp', 'tokyo.jp'], wildcards: ['kawasaki.jp'], exceptions: ['city.kawasaki.jp'] };

  it('renderPslGeneratedTs の出力の先頭（最初の export より前）に MPL 2.0 の表示と、元のファイルの URL があること', () => {
    expect(PSL_UPSTREAM_URL).toBe('https://publicsuffix.org/list/public_suffix_list.dat');
    expectMplHeader(renderPslGeneratedTs(rules));
  });

  it('表示はコメントの中にあり、ルールの中身（export する一覧）は変わらないこと', () => {
    const text = renderPslGeneratedTs(rules);
    const head = headOf(text);
    // 先頭はコメントで始まり、表示の行より前にコードが無い
    expect(head.trimStart().startsWith('/*') || head.trimStart().startsWith('//')).toBe(true);
    const mplAt = text.indexOf('Mozilla Public License');
    const lastCommentEnd = head.lastIndexOf('*/');
    expect(mplAt).toBeGreaterThanOrEqual(0);
    expect(lastCommentEnd === -1 || mplAt < lastCommentEnd).toBe(true);
    expect(text).toContain("export const PSL_SOURCE: 'snapshot' | 'fallback' = 'snapshot';");
    expect(text).toMatch(/export const PUBLIC_SUFFIX_LIST: readonly string\[\] = \[[\s\S]*"tokyo\.jp"[\s\S]*"co\.jp"/);
    expect(text).toMatch(/export const PUBLIC_SUFFIX_WILDCARDS: readonly string\[\] = \[\s*"kawasaki\.jp"\s*\]/);
    expect(text).toMatch(/export const PUBLIC_SUFFIX_EXCEPTIONS: readonly string\[\] = \[\s*"city\.kawasaki\.jp"\s*\]/);
  });

  it('同じ入力から同じ出力になること（決定的。生成日時などを埋め込まない）', () => {
    expect(renderPslGeneratedTs(rules)).toBe(renderPslGeneratedTs(structuredClone(rules)));
  });

  it('writeGeneratedPslModule でスナップショットから書き出したファイルの先頭にも表示があること', () => {
    const dir = mkTemp('wi-t06-psl-');
    const snapshotPath = path.join(dir, 'public_suffix_list.dat');
    const outputPath = path.join(dir, 'psl-rules.generated.ts');
    fs.copyFileSync(PSL_FIXTURE_PATH, snapshotPath);
    const res = writeGeneratedPslModule({ snapshotPath, outputPath, warn: () => {} });
    expect(res.source).toBe('snapshot');
    expectMplHeader(fs.readFileSync(outputPath, 'utf-8'));
  });

  it('リポジトリの src/security/psl-rules.generated.ts の先頭（2,000 文字以内）に MPL 2.0 の表示と元の URL があること', () => {
    const text = fs.readFileSync(PSL_GENERATED_PATH, 'utf-8');
    const head = text.slice(0, 2000);
    expect(head).toContain('Mozilla Public License');
    expect(head).toContain(PSL_UPSTREAM_URL);
  });
});
