/**
 * v1.8.1 T02: OS のライフサイクル表と対応表を DB に組み込む（build-db / fetch-upstream / validateDb / DB だけのリリースの予行）
 *
 * - 受け入れ条件「distro-map の全項目に evidenceUrl と verifiedAt がある」「同じ系統・製品・上流版が複数リリースにあっても表現できる」
 *   「build-db --check が通る（決定的な出力）」「DB だけのリリースの予行が通る」を、合成の入力で確かめる。
 * - ネットワークには出ない。endoflife.date の応答は偽の fetch で返す。応答の形は設計メモ（docs/dev/v1.8.1/design/T02.md の「外部の事実」）のとおり。
 * - 合成の日付は 2090 年代（実データの日付ではないことが分かるように）。DB の版・件数・dataVersion は直接書かない。
 */

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { buildDatabase, loadUpstream, OUTPUT_SCHEMA_VERSION } from '../scripts/advisories/build-db.mjs';
import { fetchUpstream, parseArgs } from '../scripts/advisories/fetch-upstream.mjs';
import { createFetchJson } from '../scripts/advisories/lib/http.mjs';
import { validateDb } from '../scripts/validate-advisories.mjs';
import { bumpAdvisoryDb, rehearseDbRelease } from '../scripts/ci/rehearse-db-release.mjs';
import { fixtureCatalog, fixtureCurated, fixtureUpstream } from './fixtures/advisory-upstream.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// 生成の基準日は、合成の上流スナップショット（tests/fixtures/advisory-upstream.mjs）の取得日時に合わせる（validateDb は未来の generatedAt を拒否する）
const GENERATED_AT = fixtureUpstream.manifest.fetchedAt;
const AS_OF = GENERATED_AT.slice(0, 10);
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');

const tempDirs = [];
const mkTemp = (prefix) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
};
afterEach(() => {
  while (tempDirs.length > 0) fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 合成の入力
// ---------------------------------------------------------------------------

/** catalog.json の OS の節（distros）。キーは系統、slug は endoflife.date の製品名 */
const distroCatalog = {
  ...fixtureCatalog,
  distros: {
    ubuntu: { name: 'Ubuntu', eol: { slug: 'ubuntu' }, releases: ['20.04', '22.04'] },
    debian: { name: 'Debian', eol: { slug: 'debian' }, releases: ['12'] },
    rhel: { name: 'Red Hat Enterprise Linux', eol: { slug: 'rhel' }, releases: ['9'] },
  },
  // T05: distro 節を作るときは出典の定義（distro._source の元）が必要になった。値は合成
  distroSources: [
    { name: 'OSV.dev (Debian Security Tracker)', url: 'https://osv.dev/list?ecosystem=Debian', ecosystem: 'Debian', license: null, licenseNote: '合成: 次の版で確認' },
    { name: 'OSV.dev (Ubuntu Security Notices)', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0' },
    { name: 'endoflife.date', url: 'https://endoflife.date/', ecosystem: null, license: 'MIT' },
  ],
};

/** endoflife.date の /api/<slug>.json の 1 サイクル分（実際の応答と同じ項目名。値は合成） */
const eolCycle = (o) => ({ releaseDate: '2090-04-01', latestReleaseDate: '2090-05-01', link: 'https://endoflife.date/', ...o });

const RAW_EOL = {
  ubuntu: [
    eolCycle({ cycle: '23.10', codename: 'Synthetic Interim', lts: false, eol: '2091-07-01', support: '2091-07-01', extendedSupport: false, latest: '23.10' }),
    eolCycle({ cycle: '22.04', codename: 'Jammy Jellyfish', lts: true, eol: '2097-06-01', support: '2094-09-30', extendedSupport: '2102-04-21', latest: '22.04.5' }),
    eolCycle({ cycle: '20.04', codename: 'Focal Fossa', lts: true, eol: '2095-05-31', support: '2092-10-01', extendedSupport: '2100-04-23', latest: '20.04.6' }),
  ],
  debian: [
    eolCycle({ cycle: '12', codename: 'Bookworm', lts: false, eol: '2098-06-30', support: '2096-07-11', extendedSupport: false, latest: '12.15' }),
    eolCycle({ cycle: '11', codename: 'Bullseye', lts: false, eol: '2096-08-31', support: '2094-08-14', extendedSupport: '2101-06-30', latest: '11.11' }),
  ],
  rhel: [eolCycle({ cycle: '9', lts: '2102-05-31', eol: '2102-05-31', support: '2097-05-31', extendedSupport: '2106-05-31', latest: '9.9' })],
};

/** fetch-upstream が保存する形（upstream/distro-eol/<slug>.json）に、偽の fetch を通して変換する */
async function compactViaFetch(rawBySlug) {
  const dir = mkTemp('wi-distro-compact-');
  const fetchJson = createFetchJson({ fetchImpl: fakeEndoflife(rawBySlug).fetchImpl, retries: 0 });
  await fetchUpstream({
    catalog: { products: {}, distros: distroCatalog.distros },
    curated: { products: {} },
    upstreamDir: dir,
    fetchJson,
    now: new Date('2090-06-01T00:00:00Z'),
    args: { distroOnly: true },
    log: () => {},
  });
  return loadUpstream(dir).distroEol;
}

const mapEntry = (o = {}) => ({
  family: 'ubuntu',
  release: 'ubuntu:20.04',
  codename: 'focal',
  product: 'nginx',
  upstreamVersions: ['1.18.0'],
  sourcePackage: 'nginx',
  verifiedAt: '2090-01-15',
  evidenceUrl: 'https://launchpad.net/ubuntu/+source/nginx/+publishinghistory',
  ...o,
});

/** 同じ「系統・製品・上流版」（ubuntu・nginx・1.18.0）が 2 つのリリースにある対応表 */
const distroMap = {
  schemaVersion: 1,
  entries: [
    mapEntry(),
    mapEntry({ release: 'ubuntu:22.04', codename: 'jammy' }),
    mapEntry({ release: 'ubuntu:22.04', codename: 'jammy', product: 'apache', upstreamVersions: ['2.4.52'], sourcePackage: 'apache2', evidenceUrl: 'https://launchpad.net/ubuntu/+source/apache2/+publishinghistory' }),
    mapEntry({ family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'php', upstreamVersions: ['8.2.7', '8.2.18'], sourcePackage: 'php8.2', evidenceUrl: 'https://tracker.debian.org/pkg/php8.2' }),
    mapEntry({ family: 'rhel', release: 'rhel:9', codename: null, product: 'openssl', upstreamVersions: ['3.0.7'], sourcePackage: 'openssl', evidenceUrl: 'https://access.redhat.com/support/policy/updates/rhel-app-streams-life-cycle' }),
  ],
};

function fakeEndoflife(rawBySlug, { failSlugs = [] } = {}) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    const m = url.match(/^https:\/\/endoflife\.date\/api\/([^/]+)\.json$/);
    if (m && rawBySlug[decodeURIComponent(m[1])] && !failSlugs.includes(decodeURIComponent(m[1]))) {
      return { ok: true, status: 200, text: async () => JSON.stringify(rawBySlug[decodeURIComponent(m[1])]) };
    }
    return { ok: false, status: 404, text: async () => '{}' };
  };
  return { calls, fetchImpl };
}

const buildWith = ({ catalog = distroCatalog, distroEol, map = distroMap } = {}) =>
  buildDatabase({
    catalog,
    curated: fixtureCurated,
    upstream: { ...fixtureUpstream, ...(distroEol ? { distroEol } : {}) },
    previousDb: null,
    asOf: AS_OF,
    generatedAt: GENERATED_AT,
    distroMap: map,
  });

const buildPlain = () =>
  buildDatabase({
    catalog: fixtureCatalog,
    curated: fixtureCurated,
    upstream: fixtureUpstream,
    previousDb: null,
    asOf: AS_OF,
    generatedAt: GENERATED_AT,
  });

/** validateDb の最低製品数を満たすための合成の製品（tests/advisory-pipeline.test.mjs と同じ考え方） */
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

/** integrity を付け直した、validateDb に通せる DB（libraries に合成の製品を足す） */
function padded(db) {
  const out = structuredClone(db);
  out.libraries = { ...out.libraries, ...padProducts() };
  return bumpAdvisoryDb(out);
}

// ---------------------------------------------------------------------------
// schema 2.3
// ---------------------------------------------------------------------------

describe('T02: schema 2.3（H7）', () => {
  it('build-db の出力スキーマは 2.3 で、生成した DB の schemaVersion もそうであること', () => {
    expect(OUTPUT_SCHEMA_VERSION).toBe('2.3');
    expect(buildPlain().db.schemaVersion).toBe('2.3');
  });

  it('validateDb は schema 2.3 の DB を受け付け、distro 節が無い 2.3 の DB も受け付けること（追加だけの互換）', () => {
    const { db } = buildPlain();
    expect(db.distro).toBeUndefined();
    expect(() => validateDb(padded(db))).not.toThrow();
    // 2.2（distro 節の無い旧 DB）もこれまでどおり通る
    expect(() => validateDb(padded({ ...db, schemaVersion: '2.2' }))).not.toThrow();
  });

  it.each([
    ['origin が不正', (db) => (db.libraries.dummy0.versions[0].origin = 'bogus')],
    ['fixStatus が不正', (db) => (db.libraries.dummy0.versions[0].fixStatus = 'bogus')],
    ['eol.eolDate が YYYY-MM-DD でない', (db) => (db.libraries.dummy0.eol = [{ cycle: '1', eolDate: '2090/01/01', status: 'EOL' }])],
  ])('validateDb は schema 2.3 でも 2.2 と同じ厳格な検査をすること（%s なら拒否。陰性）', (_label, mutate) => {
    const db = padded(buildPlain().db);
    expect(db.schemaVersion).toBe('2.3');
    mutate(db);
    expect(() => validateDb({ ...db, integrity: undefined })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// distro.releases（ライフサイクル）
// ---------------------------------------------------------------------------

describe('T02: build-db が distro.releases（OS のライフサイクル）を出力する', () => {
  it('catalog の OS の節に載っているリリースだけを、標準サポート終了と延長サポート終了の両方とともに出すこと（陽性）', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const { db } = buildWith({ distroEol });
    const releases = db.distro.releases;
    const byId = Object.fromEntries(releases.map((r) => [r.release, r]));

    expect(Object.keys(byId).sort()).toEqual(['debian:12', 'rhel:9', 'ubuntu:20.04', 'ubuntu:22.04']);
    expect(byId['ubuntu:22.04']).toMatchObject({
      family: 'ubuntu',
      cycle: '22.04',
      codename: 'Jammy Jellyfish',
      lts: true,
      releaseDate: '2090-04-01',
      standardSupportEnd: '2097-06-01',
      extendedSupportEnd: '2102-04-21',
    });
    expect(byId['ubuntu:20.04']).toMatchObject({ standardSupportEnd: '2095-05-31', extendedSupportEnd: '2100-04-23' });
    // 延長サポートが無い（false）ものは null
    expect(byId['debian:12']).toMatchObject({ family: 'debian', cycle: '12', standardSupportEnd: '2098-06-30', extendedSupportEnd: null });
    // codename の無い系統は null
    expect(byId['rhel:9']).toMatchObject({ family: 'rhel', cycle: '9', codename: null, standardSupportEnd: '2102-05-31', extendedSupportEnd: '2106-05-31' });
  });

  it('catalog に無いサイクル（取得結果にだけある 23.10、debian 11）は出さないこと（陰性）', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const ids = buildWith({ distroEol }).db.distro.releases.map((r) => r.release);
    expect(ids).not.toContain('ubuntu:23.10');
    expect(ids).not.toContain('debian:11');
  });

  it('取得結果の codename に HTML の特殊文字があっても、DB には安全な文字列だけが入ること', async () => {
    const raw = structuredClone(RAW_EOL);
    raw.ubuntu[1].codename = '<img src=x onerror=alert(1)>Jammy';
    const distroEol = await compactViaFetch(raw);
    const r = buildWith({ distroEol }).db.distro.releases.find((x) => x.release === 'ubuntu:22.04');
    expect(r.codename).not.toMatch(/[<>"'`]/);
    expect(r.codename).toContain('Jammy');
  });

  it('OS のライフサイクルの取得結果がまだ無いとき、失敗せず distro.releases を空にし、警告を build-report に残すこと', () => {
    let out;
    expect(() => {
      out = buildWith({ distroEol: undefined });
    }).not.toThrow();
    expect(out.db.distro.releases).toEqual([]);
    expect(out.report.distro.warnings.length).toBeGreaterThan(0);
    // 対応表は取得結果が無くても出す
    expect(out.db.distro.map.length).toBe(distroMap.entries.length);
  });

  it('一部の系統だけ取得結果が無いときは、ある系統のリリースだけを出し、無い系統を警告に書くこと', async () => {
    const distroEol = await compactViaFetch({ ubuntu: RAW_EOL.ubuntu, rhel: RAW_EOL.rhel });
    const out = buildWith({ distroEol });
    const families = new Set(out.db.distro.releases.map((r) => r.family));
    expect(families.has('ubuntu')).toBe(true);
    expect(families.has('debian')).toBe(false);
    expect(out.report.distro.warnings.join('\n')).toMatch(/debian/);
  });

  it('既存の製品の結果（libraries・coverage・integrity.digest）は、OS の節を足しても変わらないこと', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const withDistro = buildWith({ distroEol }).db;
    const plain = buildPlain().db;
    expect(withDistro.libraries).toEqual(plain.libraries);
    expect(withDistro.coverage).toEqual(plain.coverage);
    expect(withDistro.integrity.digest).toBe(plain.integrity.digest);
    expect(withDistro.integrity.digest).toBe(sha256(JSON.stringify(withDistro.libraries)));
    // OS は libraries の製品にならない
    for (const family of Object.keys(distroCatalog.distros)) expect(withDistro.libraries[family]).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// distro.map（対応表）
// ---------------------------------------------------------------------------

describe('T02: build-db が distro.map（上流版→リリースの対応表）を出力する', () => {
  it('同じ「系統・製品・上流版」が複数のリリースにある場合も、まとめたり捨てたりせず両方を出すこと（受け入れ条件 2）', () => {
    const { db } = buildWith();
    const hits = db.distro.map.filter((e) => e.family === 'ubuntu' && e.product === 'nginx' && e.upstreamVersions.includes('1.18.0'));
    expect(hits.map((e) => e.release).sort()).toEqual(['ubuntu:20.04', 'ubuntu:22.04']);
  });

  it('対応表の全項目が、evidenceUrl と verifiedAt を含む 8 つの項目を保ったまま DB に入ること（受け入れ条件 1）', () => {
    const { db } = buildWith();
    expect(db.distro.map).toHaveLength(distroMap.entries.length);
    for (const src of distroMap.entries) {
      const found = db.distro.map.find((e) => e.release === src.release && e.product === src.product && e.sourcePackage === src.sourcePackage);
      expect(found, `${src.release} ${src.product}`).toBeDefined();
      expect(found).toMatchObject({
        family: src.family,
        release: src.release,
        codename: src.codename,
        product: src.product,
        upstreamVersions: src.upstreamVersions,
        sourcePackage: src.sourcePackage,
        verifiedAt: src.verifiedAt,
        evidenceUrl: src.evidenceUrl,
      });
    }
  });

  it('同じ入力からは同じ出力になる（決定的。build-db --check が通る前提）こと', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    expect(JSON.stringify(buildWith({ distroEol }).db)).toBe(JSON.stringify(buildWith({ distroEol }).db));
  });

  const broken = [
    ['evidenceUrl が無い', (e) => delete e.evidenceUrl],
    ['verifiedAt が無い', (e) => delete e.verifiedAt],
    ['evidenceUrl が空文字', (e) => (e.evidenceUrl = '')],
    ['evidenceUrl が http', (e) => (e.evidenceUrl = 'http://launchpad.net/ubuntu/+source/nginx')],
    ['evidenceUrl が javascript:', (e) => (e.evidenceUrl = 'javascript:alert(1)')],
    ['evidenceUrl が一次資料でないホスト', (e) => (e.evidenceUrl = 'https://mirror.example.test/nginx')],
    ['verifiedAt が YYYY-MM-DD でない', (e) => (e.verifiedAt = '2090/01/15')],
    ['upstreamVersions が空', (e) => (e.upstreamVersions = [])],
    ['upstreamVersions に Debian の revision 付きの版', (e) => (e.upstreamVersions = ['1.18.0-6ubuntu14'])],
    ['release が family と食い違う', (e) => (e.release = 'debian:12')],
    ['release が catalog の OS の節に無い', (e) => (e.release = 'ubuntu:99.04')],
    ['product が対象外', (e) => (e.product = 'tomcat')],
  ];

  it.each(broken)('対応表の項目が不正（%s）なら build-db は失敗すること（陰性）', (_label, mutate) => {
    const map = structuredClone(distroMap);
    mutate(map.entries[0]);
    expect(() => buildWith({ map })).toThrow();
  });

  it('同じ「リリース・製品・ソースパッケージ」の項目が 2 つあると build-db は失敗すること（陰性）', () => {
    const map = structuredClone(distroMap);
    map.entries.push(mapEntry({ upstreamVersions: ['1.17.10'] }));
    expect(() => buildWith({ map })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// integrity と validateDb
// ---------------------------------------------------------------------------

describe('T02: integrity に distro 節を含める', () => {
  it('distro 節があるとき、integrity は libraries の digest に加えて distro の digest を持つこと', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const { db } = buildWith({ distroEol });
    expect(db.integrity).toMatchObject({ algorithm: 'sha256', target: 'libraries', digest: sha256(JSON.stringify(db.libraries)) });
    expect(db.integrity.distroDigest).toBe(sha256(JSON.stringify(db.distro)));
  });

  it('distro 節が無いときは distroDigest を持たないこと', () => {
    const { db } = buildPlain();
    expect(db.integrity.distroDigest).toBeUndefined();
  });

  it('distro 節の中身が変われば distroDigest も変わること', () => {
    const a = buildWith().db;
    const map = structuredClone(distroMap);
    map.entries[0].upstreamVersions = ['1.18.0', '1.17.10'];
    const b = buildWith({ map }).db;
    expect(b.integrity.distroDigest).not.toBe(a.integrity.distroDigest);
    expect(b.integrity.digest).toBe(a.integrity.digest);
  });

  it('validateDb は distro 節を含む DB を受け付け、distro 節を書き換えると integrity で拒否すること', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const good = padded(buildWith({ distroEol }).db);
    expect(() => validateDb(good)).not.toThrow();

    const tampered = structuredClone(good);
    tampered.distro.map[0].upstreamVersions.push('9.9.9');
    expect(() => validateDb(tampered)).toThrow(/integrity/);

    // distroDigest を消して改ざんを隠すこともできない
    const stripped = structuredClone(tampered);
    delete stripped.integrity.distroDigest;
    expect(() => validateDb(stripped)).toThrow(/integrity/);
  });

  it.each([
    ['対応表の項目に evidenceUrl が無い', (db) => delete db.distro.map[0].evidenceUrl],
    ['対応表の項目に verifiedAt が無い', (db) => delete db.distro.map[0].verifiedAt],
    ['対応表の evidenceUrl が https でない', (db) => (db.distro.map[0].evidenceUrl = 'http://launchpad.net/')],
    ['ライフサイクルの codename に HTML の特殊文字', (db) => (db.distro.releases[0].codename = '<b>x</b>')],
    ['distro.releases が配列でない', (db) => (db.distro.releases = {})],
    ['distro.map が配列でない', (db) => (db.distro.map = null)],
  ])('validateDb は distro 節の形が不正（%s）なら拒否すること（陰性）', async (_label, mutate) => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const db = structuredClone(buildWith({ distroEol }).db);
    db.libraries = { ...db.libraries, ...padProducts() };
    mutate(db);
    expect(() => validateDb({ ...db, integrity: undefined })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// loadUpstream / fetch-upstream
// ---------------------------------------------------------------------------

describe('T02: loadUpstream が OS のライフサイクルの取得結果を読む', () => {
  it('upstream/distro-eol/<slug>.json を distroEol[slug] として読み、無ければ空のオブジェクトになること', () => {
    const dir = mkTemp('wi-upstream-distro-');
    fs.mkdirSync(path.join(dir, 'distro-eol'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'distro-eol', 'ubuntu.json'), JSON.stringify({ slug: 'ubuntu', fetchedAt: '2090-06-01T00:00:00.000Z', cycles: [{ cycle: '22.04', eol: '2097-06-01' }] }));
    const up = loadUpstream(dir);
    expect(Object.keys(up.distroEol)).toEqual(['ubuntu']);
    expect(up.distroEol.ubuntu.cycles).toHaveLength(1);

    expect(loadUpstream(mkTemp('wi-upstream-empty-')).distroEol).toEqual({});
  });
});

describe('T02: fetch-upstream --distro-only（OS のライフサイクルだけを取る。fetch は偽物）', () => {
  it('--distro-only を解釈し、既定では無効であること', () => {
    expect(parseArgs(['node', 'fetch-upstream.mjs', '--distro-only']).distroOnly).toBe(true);
    expect(parseArgs(['node', 'fetch-upstream.mjs']).distroOnly).toBe(false);
  });

  /** 前回の取得結果（製品の EOL・OSV・manifest）がある upstream ディレクトリ */
  function seedUpstream() {
    const dir = mkTemp('wi-fetch-distro-');
    const write = (rel, obj) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), JSON.stringify(obj));
    };
    write('eol/jquery.json', { slug: 'jquery', fetchedAt: '2090-01-01T00:00:00.000Z', cycles: [{ cycle: '3', eol: false }] });
    write('osv/npm__jquery.json', { package: { ecosystem: 'npm', name: 'jquery' }, fetchedAt: '2090-01-01T00:00:00.000Z', vulns: [] });
    write('kev.json', { count: 0, vulns: [] });
    write('manifest.json', {
      schemaVersion: 1,
      fetchedAt: '2090-01-01T00:00:00.000Z',
      sources: {
        'eol:jquery': { status: 'ok', count: 1, fetchedAt: '2090-01-01T00:00:00.000Z' },
        'osv:npm:jquery': { status: 'ok', count: 0, fetchedAt: '2090-01-01T00:00:00.000Z' },
        kev: { status: 'ok', count: 0, fetchedAt: '2090-01-01T00:00:00.000Z' },
      },
    });
    return dir;
  }

  const listFiles = (dir) => {
    const out = {};
    const walk = (d) => {
      for (const ent of fs.readdirSync(d, { withFileTypes: true })) {
        const abs = path.join(d, ent.name);
        if (ent.isDirectory()) walk(abs);
        else out[path.relative(dir, abs).split(path.sep).join('/')] = fs.readFileSync(abs, 'utf-8');
      }
    };
    walk(dir);
    return out;
  };

  const catalogWithDistros = { ...distroCatalog, products: { jquery: fixtureCatalog.products.jquery } };

  it('endoflife.date の OS の製品だけを取り、upstream/distro-eol/ に保存し、既存の製品の取得結果と manifest の取得日時を変えないこと', async () => {
    const dir = seedUpstream();
    const before = listFiles(dir);
    const prevManifest = JSON.parse(before['manifest.json']);
    const fake = fakeEndoflife(RAW_EOL);

    await fetchUpstream({
      catalog: catalogWithDistros,
      curated: { products: {} },
      upstreamDir: dir,
      fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
      now: new Date('2090-06-01T00:00:00Z'),
      args: { distroOnly: true },
      log: () => {},
    });

    // 取りに行ったのは OS の slug の endoflife.date だけ（OSV・NVD・KEV・製品の EOL には出ない）
    expect(fake.calls.length).toBeGreaterThan(0);
    for (const u of fake.calls) expect(u).toMatch(/^https:\/\/endoflife\.date\/api\/(ubuntu|debian|rhel)\.json$/);
    expect(new Set(fake.calls)).toEqual(new Set(['ubuntu', 'debian', 'rhel'].map((s) => `https://endoflife.date/api/${s}.json`)));

    const after = listFiles(dir);
    // 既存の製品の取得結果はそのまま
    for (const rel of ['eol/jquery.json', 'osv/npm__jquery.json', 'kev.json']) expect(after[rel]).toBe(before[rel]);
    // OS のライフサイクルは別のディレクトリに入り、製品の eol/ には混ざらない
    expect(Object.keys(after).filter((k) => k.startsWith('eol/'))).toEqual(['eol/jquery.json']);
    const ubuntu = JSON.parse(after['distro-eol/ubuntu.json']);
    expect(ubuntu.slug).toBe('ubuntu');
    const jammy = ubuntu.cycles.find((c) => c.cycle === '22.04');
    expect(jammy).toMatchObject({ cycle: '22.04', codename: 'Jammy Jellyfish', eol: '2097-06-01', extendedSupport: '2102-04-21', lts: true, releaseDate: '2090-04-01' });

    // manifest: 取得日時（build-db の基準日）は前回のまま。前回の製品の記録も残り、OS の記録が足される
    const manifest = JSON.parse(after['manifest.json']);
    expect(manifest.fetchedAt).toBe(prevManifest.fetchedAt);
    for (const [k, v] of Object.entries(prevManifest.sources)) expect(manifest.sources[k]).toEqual(v);
    for (const slug of ['ubuntu', 'debian', 'rhel']) expect(manifest.sources[`distro-eol:${slug}`]).toMatchObject({ status: 'ok' });
  });

  it('OS の 1 つの取得に失敗しても続け、失敗を manifest に記録し、ほかの OS は保存すること', async () => {
    const dir = seedUpstream();
    const fake = fakeEndoflife(RAW_EOL, { failSlugs: ['debian'] });
    const res = await fetchUpstream({
      catalog: catalogWithDistros,
      curated: { products: {} },
      upstreamDir: dir,
      fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
      now: new Date('2090-06-01T00:00:00Z'),
      args: { distroOnly: true },
      log: () => {},
    });
    expect(res.failCount).toBe(1);
    expect(res.manifest.sources['distro-eol:debian'].status).not.toBe('ok');
    expect(res.manifest.sources['distro-eol:ubuntu']).toMatchObject({ status: 'ok' });
    expect(fs.existsSync(path.join(dir, 'distro-eol', 'ubuntu.json'))).toBe(true);
    expect(fs.existsSync(path.join(dir, 'distro-eol', 'debian.json'))).toBe(false);
  });

  it('--distro-only でない通常の取得でも、OS のライフサイクルを取ること（週次の更新で古くならない）', async () => {
    const dir = mkTemp('wi-fetch-full-');
    const urls = [];
    const fetchImpl = async (url, init) => {
      urls.push(url);
      if (url.startsWith('https://endoflife.date/')) return fakeEndoflife(RAW_EOL).fetchImpl(url, init);
      if (url.startsWith('https://www.cisa.gov/')) return { ok: true, status: 200, text: async () => JSON.stringify({ catalogVersion: 'x', dateReleased: '2090-01-01T00:00:00Z', vulnerabilities: [] }) };
      return { ok: true, status: 200, text: async () => JSON.stringify({ vulns: [] }) };
    };
    await fetchUpstream({
      catalog: catalogWithDistros,
      curated: { products: {} },
      upstreamDir: dir,
      fetchJson: createFetchJson({ fetchImpl, retries: 0 }),
      now: new Date('2090-06-01T00:00:00Z'),
      args: { skipNvd: true },
      log: () => {},
    });
    expect(urls).toContain('https://endoflife.date/api/ubuntu.json');
    expect(urls).toContain('https://endoflife.date/api/jquery.json');
    expect(fs.existsSync(path.join(dir, 'distro-eol', 'ubuntu.json'))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// DB だけのリリースの予行（distro 節を含む）
// ---------------------------------------------------------------------------

describe('T02: DB だけのリリースの予行が distro 節を含んだ状態で通る（受け入れ条件 4）', () => {
  it('bumpAdvisoryDb は distro 節を変えずに distroDigest を計算し直し、distro 節が無ければ distroDigest を付けないこと', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const { db } = buildWith({ distroEol });
    const stale = { ...structuredClone(db), integrity: { ...db.integrity, distroDigest: '0'.repeat(64) } };
    const bumped = bumpAdvisoryDb(stale);
    expect(bumped.distro).toEqual(db.distro);
    expect(bumped.integrity.digest).toBe(sha256(JSON.stringify(db.libraries)));
    expect(bumped.integrity.distroDigest).toBe(sha256(JSON.stringify(db.distro)));
    expect(bumped.dataVersion > db.dataVersion).toBe(true);

    const plainBumped = bumpAdvisoryDb(buildPlain().db);
    expect(plainBumped.integrity.distroDigest).toBeUndefined();
  });

  it('distro 節を含む合成の作業ツリーで予行が通り、コピーの DB の integrity（libraries と distro）が正しいこと', async () => {
    const distroEol = await compactViaFetch(RAW_EOL);
    const { db } = buildWith({ distroEol });
    const root = mkTemp('wi-rehearsal-distro-');
    const write = (rel, text) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), text);
    };
    // 合成の版（同梱の package.json の版ではない）
    write('package.json', `${JSON.stringify({ name: 'synthetic', version: '3.4.5', type: 'module' })}\n`);
    write('public/manifest.json', `${JSON.stringify({ manifest_version: 3, name: 'Synthetic', version: '3.4.5' })}\n`);
    write('data/synthetic-db.json', `${JSON.stringify(db, null, 2)}\n`);
    for (const rel of ['scripts/advisories/bump-db-revision.mjs', 'scripts/advisories/lib/util.mjs']) {
      write(rel, fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8'));
    }
    write(
      'check.mjs',
      `import crypto from 'node:crypto';
import fs from 'node:fs';
const db = JSON.parse(fs.readFileSync('data/synthetic-db.json', 'utf-8'));
const h = (v) => crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
const errors = [];
if (!db.distro || !Array.isArray(db.distro.map) || db.distro.map.length === 0) errors.push('distro 節がありません');
if (db.integrity.digest !== h(db.libraries)) errors.push('libraries の digest が一致しません');
if (db.integrity.distroDigest !== h(db.distro)) errors.push('distro の digest が一致しません');
if (errors.length) { console.error(errors.join('\\n')); process.exit(1); }
`
    );
    const r = await rehearseDbRelease({ sourceDir: root, advisoryDbPath: 'data/synthetic-db.json', testCommand: [process.execPath, 'check.mjs'] });
    expect(r.ok, '予行が失敗しました').toBe(true);
    expect(r.dataVersion > r.previousDataVersion).toBe(true);
    // 予行の前の DB（元の作業ツリー）は変わらない
    expect(JSON.parse(fs.readFileSync(path.join(root, 'data/synthetic-db.json'), 'utf-8'))).toEqual(db);
  });

});

// ---------------------------------------------------------------------------
// 本番の入力（catalog.json と distro-map.json）から build-db が通る
// ---------------------------------------------------------------------------

describe('T02: 本番の catalog.json と distro-map.json で build-db が通る', () => {
  it('OS のライフサイクルの取得結果が無くても、本番の入力から DB を作れて validateDb を通り、対応表の全項目が入ること', () => {
    const catalog = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'data/advisories/catalog.json'), 'utf-8'));
    const map = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'data/advisories/distro-map.json'), 'utf-8'));
    const { db, report } = buildDatabase({
      catalog,
      curated: fixtureCurated,
      upstream: fixtureUpstream,
      previousDb: null,
      asOf: AS_OF,
      generatedAt: GENERATED_AT,
      distroMap: map,
    });
    expect(db.distro.map).toHaveLength(map.entries.length);
    expect(db.distro.releases).toEqual([]);
    expect(report.distro.warnings.length).toBeGreaterThan(0);
    expect(() => validateDb(padded(db))).not.toThrow();
  });

  it('build-db の CLI は distro-map.json を読む（PATHS.distroMap がリポジトリの data/advisories/distro-map.json を指す）こと', async () => {
    const { PATHS } = await import('../scripts/advisories/lib/util.mjs');
    expect(path.relative(REPO_ROOT, PATHS.distroMap).split(path.sep).join('/')).toBe('data/advisories/distro-map.json');
  });

  it('build-db の CLI の --check は、upstream の OS の取得結果が無い作業ツリーでも警告だけで成功すること', () => {
    // 一時コピーに必要なファイルだけを置き、まず生成、続けて --check を走らせる（ネットワークに出ない）
    const root = mkTemp('wi-builddb-cli-');
    const copy = (rel) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(root, rel));
    };
    for (const f of fs.readdirSync(path.join(REPO_ROOT, 'scripts/advisories/lib'))) copy(`scripts/advisories/lib/${f}`);
    for (const rel of ['scripts/advisories/build-db.mjs', 'data/advisories/catalog.json', 'data/advisories/curated.json', 'data/advisories/distro-map.json']) copy(rel);
    fs.mkdirSync(path.join(root, 'src/detection'), { recursive: true });
    fs.mkdirSync(path.join(root, 'data/advisories/upstream'), { recursive: true });
    fs.writeFileSync(path.join(root, 'data/advisories/upstream/manifest.json'), JSON.stringify({ schemaVersion: 1, fetchedAt: GENERATED_AT, sources: {} }));
    const script = path.join(root, 'scripts/advisories/build-db.mjs');
    const gen = execFileSync(process.execPath, [script], { cwd: root, encoding: 'utf-8', stdio: 'pipe' });
    expect(typeof gen).toBe('string');
    const outDb = JSON.parse(fs.readFileSync(path.join(root, 'src/detection', ['advisory-db', 'json'].join('.')), 'utf-8'));
    expect(outDb.schemaVersion).toBe(OUTPUT_SCHEMA_VERSION);
    expect(outDb.distro.releases).toEqual([]);
    expect(outDb.distro.map.length).toBeGreaterThan(0);
    expect(() => execFileSync(process.execPath, [script, '--check'], { cwd: root, encoding: 'utf-8', stdio: 'pipe' })).not.toThrow();
  });
});
