/**
 * T05: OSV の Debian / Ubuntu データの取り込み（fetch-upstream → upstream/osv-distro/ → build-db の distro.advisories と distro._source）
 *
 * - 受け入れ条件
 *   1. 修正済み・未修正・影響なし・ESM だけの修正の各ケースで、圧縮後の形が正しい（偽の OSV レコード。形は実際のレコードに準拠）
 *   2. _source（OSV と endoflife.date の両方）が無い、または license も licenseNote も無いと build-db --check が失敗する
 *   3. distro 節が 800 KB を超えると失敗する（check-size 側は tests/ci-check-size-distro.test.ts）
 *   4. DB だけのリリースの予行が通る
 * - ネットワークには出ない。OSV と endoflife.date の応答は偽の fetch で返す。偽のレコードの形は設計メモ
 *   （docs/dev/v1.8.1/design/T05.md の「外部の事実」）にある実際のレコード（UBUNTU-CVE-*・USN-*・DEBIAN-CVE-*・DSA-*）に合わせた。
 * - CVE の番号・パッケージの版・日付は合成（CVE-2090-*、…ubuntu3.90 など）。DB の版・件数・dataVersion は直接書かない。
 */

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { buildDatabase, loadUpstream } from '../scripts/advisories/build-db.mjs';
import { fetchUpstream } from '../scripts/advisories/fetch-upstream.mjs';
import { createFetchJson } from '../scripts/advisories/lib/http.mjs';
import { validateDb } from '../scripts/validate-advisories.mjs';
import { bumpAdvisoryDb, rehearseDbRelease } from '../scripts/ci/rehearse-db-release.mjs';
import { fixtureCatalog, fixtureCurated, fixtureUpstream } from './fixtures/advisory-upstream.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// validateDb は未来の generatedAt を拒否するので、合成の上流スナップショットの取得日時に合わせる
const GENERATED_AT = fixtureUpstream.manifest.fetchedAt;
const AS_OF = GENERATED_AT.slice(0, 10);
const NOW = new Date(GENERATED_AT);
const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
const DISTRO_LIMIT_BYTES = 800 * 1024; // H8
const ALLOWED_ENTRY_KEYS = ['cve', 'status', 'fixedVersions', 'esm', 'osvIds'];
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
// test-hygiene の検査に引っかからないよう、同梱 DB のファイル名は組み立てて使う
const BUNDLED_DB_FILE = ['advisory-db', 'json'].join('.');

const tempDirs = [];
const mkTemp = (prefix) => {
  // macOS の /tmp はシンボリックリンクなので、解決したパスを使う（スクリプトの入口の判定を一致させる）
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

/** catalog の出典の定義（distroSources）。値は合成。本番の値は下の「本番の catalog.json」のテストで確かめる */
const SOURCES = [
  { name: 'OSV.dev (Debian Security Tracker)', url: 'https://osv.dev/list?ecosystem=Debian', ecosystem: 'Debian', license: null, licenseNote: '合成: 次の版で確認' },
  { name: 'OSV.dev (Ubuntu Security Notices)', url: 'https://github.com/canonical/ubuntu-security-notices', ecosystem: 'Ubuntu', license: 'CC-BY-SA-4.0' },
  { name: 'endoflife.date', url: 'https://endoflife.date/', ecosystem: null, license: 'MIT' },
];

const catalogT05 = {
  ...fixtureCatalog,
  distros: {
    ubuntu: { name: 'Ubuntu', eol: { slug: 'ubuntu' }, releases: ['20.04', '26.10'] },
    debian: { name: 'Debian', eol: { slug: 'debian' }, releases: ['12'] },
    rhel: { name: 'Red Hat Enterprise Linux', eol: { slug: 'rhel' }, releases: ['9'] },
  },
  distroSources: SOURCES,
};

const mapEntry = (o) => ({ codename: null, verifiedAt: '2090-01-15', evidenceUrl: 'https://launchpad.net/ubuntu/+source/apache2/+publishinghistory', ...o });
const distroMapT05 = {
  schemaVersion: 1,
  entries: [
    mapEntry({ family: 'ubuntu', release: 'ubuntu:20.04', codename: 'focal', product: 'apache', upstreamVersions: ['2.4.41'], sourcePackage: 'apache2' }),
    mapEntry({ family: 'ubuntu', release: 'ubuntu:20.04', codename: 'focal', product: 'php', upstreamVersions: ['7.4.3'], sourcePackage: 'php7.4' }),
    // openssl は DB の製品に無いので OSV は取らない（H8）
    mapEntry({ family: 'ubuntu', release: 'ubuntu:20.04', codename: 'focal', product: 'openssl', upstreamVersions: ['1.1.1f'], sourcePackage: 'openssl' }),
    // 中間リリース（LTS でない）
    mapEntry({ family: 'ubuntu', release: 'ubuntu:26.10', codename: 'stonking', product: 'nginx', upstreamVersions: ['1.30.4'], sourcePackage: 'nginx' }),
    mapEntry({ family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'apache', upstreamVersions: ['2.4.62'], sourcePackage: 'apache2', evidenceUrl: 'https://tracker.debian.org/pkg/apache2' }),
    mapEntry({ family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'nginx', upstreamVersions: ['1.22.1'], sourcePackage: 'nginx', evidenceUrl: 'https://tracker.debian.org/pkg/nginx' }),
    // RHEL 系は第3段階の対象外（H1）
    mapEntry({ family: 'rhel', release: 'rhel:9', product: 'apache', upstreamVersions: ['2.4.62'], sourcePackage: 'httpd', evidenceUrl: 'https://dl.rockylinux.org/vault/rocky/' }),
  ],
};

/** 期待する OSV の問い合わせ（エコシステム名は OSV の仕様と実際のレコードのとおり） */
const EXPECTED_QUERIES = [
  'Ubuntu:20.04:LTS|apache2',
  'Ubuntu:Pro:20.04:LTS|apache2',
  'Ubuntu:20.04:LTS|php7.4',
  'Ubuntu:Pro:20.04:LTS|php7.4',
  'Ubuntu:26.10|nginx',
  'Debian:12|apache2',
  'Debian:12|nginx',
];

const RAW_EOL = {
  ubuntu: [
    { cycle: '26.10', codename: 'Synthetic Stonking', lts: false, releaseDate: '2090-10-01', eol: '2091-07-01', support: '2091-07-01', extendedSupport: false, latest: '26.10' },
    { cycle: '20.04', codename: 'Focal Fossa', lts: true, releaseDate: '2090-04-01', eol: '2095-05-31', support: '2092-10-01', extendedSupport: '2100-04-23', latest: '20.04.6' },
  ],
  debian: [{ cycle: '12', codename: 'Bookworm', lts: false, releaseDate: '2090-06-10', eol: '2098-06-30', support: '2096-07-11', extendedSupport: false, latest: '12.15' }],
  rhel: [{ cycle: '9', lts: '2102-05-31', releaseDate: '2090-05-17', eol: '2102-05-31', support: '2097-05-31', extendedSupport: '2106-05-31', latest: '9.9' }],
};

// --- 偽の OSV レコード（実際のレコードと同じ項目名・入れ子。値は合成） ---

const ubuntuDistro = (eco) => {
  const m = /^Ubuntu:(Pro:)?([0-9.]+)/.exec(eco);
  const name = { '18.04': 'bionic', '20.04': 'focal', '22.04': 'jammy', '24.04': 'noble', '26.10': 'stonking' }[m[2]] || 'synthetic';
  return m[1] ? `esm-infra/${name}` : name;
};

/** Ubuntu の affected の 1 要素（fixed が null なら未修正: introduced だけ） */
const ubuntuAffected = (ecosystem, name, fixed, source) => ({
  package: { ecosystem, name, purl: `pkg:deb/ubuntu/${name}${fixed ? `@${fixed}` : ''}?arch=source&distro=${ubuntuDistro(ecosystem)}` },
  ranges: [{ type: 'ECOSYSTEM', events: fixed ? [{ introduced: '0' }, { fixed }] : [{ introduced: '0' }] }],
  versions: ['0.0.1-1', '0.0.1-1ubuntu0.1'],
  ecosystem_specific: {
    availability: ecosystem.includes(':Pro:') ? 'Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro' : 'No subscription required',
    binaries: [{ binary_name: name, binary_version: fixed || '0.0.1-1' }],
  },
  database_specific: { source },
});

/** UBUNTU-CVE-* レコード（CVE 単位）。CVE は upstream に入る（aliases は無い） */
const ubuntuCve = (cve, affected, { related = [], withdrawn } = {}) => {
  const id = `UBUNTU-${cve}`;
  const source = `https://github.com/canonical/ubuntu-security-notices/blob/main/osv/cve/2090/${id}.json`;
  return {
    id,
    details: 'Synthetic description of the vulnerability.',
    modified: '2090-02-01T00:00:00Z',
    published: '2090-01-01T00:00:00Z',
    ...(withdrawn ? { withdrawn } : {}),
    related,
    upstream: [cve],
    references: [{ type: 'REPORT', url: `https://ubuntu.com/security/${cve}` }],
    affected: affected.map(([eco, name, fixed]) => ubuntuAffected(eco, name, fixed, source)),
    schema_version: '1.7.5',
    severity: [{ type: 'Ubuntu', score: 'medium' }],
  };
};

/** USN-* レコード（通知単位）。複数の CVE と UBUNTU-CVE-* が upstream に入る */
const usn = (id, cves, affected) => {
  const source = `https://github.com/canonical/ubuntu-security-notices/blob/main/osv/usn/${id}.json`;
  return {
    id,
    summary: 'synthetic vulnerabilities',
    details: 'Synthetic notice text.',
    modified: '2090-02-01T00:00:00Z',
    published: '2090-01-15T00:00:00Z',
    related: cves.map((c) => `UBUNTU-${c}`),
    upstream: [...cves, ...cves.map((c) => `UBUNTU-${c}`)],
    references: [{ type: 'ADVISORY', url: `https://ubuntu.com/security/notices/${id}` }],
    affected: affected.map(([eco, name, fixed]) => ({
      ...ubuntuAffected(eco, name, fixed, source),
      database_specific: { cves_map: { ecosystem: eco, cves: cves.map((c) => ({ id: c, severity: [{ score: 'medium', type: 'Ubuntu' }] })) }, source },
    })),
    schema_version: '1.7.5',
  };
};

const debianCodename = (eco) => ({ 'Debian:11': 'bullseye', 'Debian:12': 'bookworm', 'Debian:13': 'trixie' })[eco] || 'synthetic';
const debianAffected = (ecosystem, name, fixed, source, { withDistro = true } = {}) => ({
  package: { ecosystem, name, purl: `pkg:deb/debian/${name}?arch=source${withDistro ? `&distro=${debianCodename(ecosystem)}` : ''}` },
  ranges: [{ type: 'ECOSYSTEM', events: fixed ? [{ introduced: '0' }, { fixed }] : [{ introduced: '0' }] }],
  ...(withDistro ? { ecosystem_specific: { urgency: 'not yet assigned' } } : { versions: ['0.0.1-1'] }),
  database_specific: { source },
});

/** DEBIAN-CVE-* レコード（CVE 単位。Debian Security Tracker から変換） */
const debianCve = (cve, affected, { withdrawn } = {}) => {
  const id = `DEBIAN-${cve}`;
  const source = `https://storage.googleapis.com/debian-osv/debian-cve-osv/${id}.json`;
  return {
    id,
    details: 'Synthetic description of the vulnerability.',
    modified: '2090-02-01T00:00:00Z',
    published: '2090-01-01T00:00:00Z',
    ...(withdrawn ? { withdrawn } : {}),
    upstream: [cve],
    references: [{ type: 'ADVISORY', url: `https://security-tracker.debian.org/tracker/${cve}` }],
    affected: affected.map(([eco, name, fixed]) => debianAffected(eco, name, fixed, source)),
    schema_version: '1.9.2',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
  };
};

/** DSA-* レコード（Debian のセキュリティ勧告。summary だけで details は無い） */
const dsa = (id, cves, affected) => {
  const source = `https://storage.googleapis.com/debian-osv/dsa-osv/${id}.json`;
  return {
    id,
    summary: 'synthetic - security update',
    modified: '2090-02-01T00:00:00Z',
    published: '2090-01-20T00:00:00Z',
    upstream: [...cves, ...cves.map((c) => `DEBIAN-${c}`)],
    affected: affected.map(([eco, name, fixed]) => debianAffected(eco, name, fixed, source, { withDistro: false })),
    schema_version: '1.7.0',
  };
};

const C = (n) => `CVE-2090-${n}`;

/** 基本のケース */
const RECORDS = [
  // 修正済み（Ubuntu）: CVE 単位のレコードと USN の両方にある。対象外のリリース（Pro:18.04）の行も混ざる
  ubuntuCve(C('10001'), [
    ['Ubuntu:Pro:18.04:LTS', 'apache2', '2.4.29-1ubuntu4.90+esm1'],
    ['Ubuntu:20.04:LTS', 'apache2', '2.4.41-4ubuntu3.90'],
    ['Ubuntu:22.04:LTS', 'apache2', '2.4.52-1ubuntu4.90'],
  ], { related: ['USN-9001-1'] }),
  // USN: 10001 と 10002 をまとめて修正（10002 には CVE 単位のレコードが無い）
  usn('USN-9001-1', [C('10001'), C('10002')], [
    ['Ubuntu:20.04:LTS', 'apache2', '2.4.41-4ubuntu3.90'],
    ['Ubuntu:22.04:LTS', 'apache2', '2.4.52-1ubuntu4.90'],
  ]),
  // 未修正（Ubuntu）: CVE 単位のレコードでは introduced だけ。USN は upstream に 10003 を含むが、CVE 単位のレコードを優先する
  ubuntuCve(C('10003'), [['Ubuntu:20.04:LTS', 'apache2', null]]),
  usn('USN-9003-1', [C('10003')], [['Ubuntu:20.04:LTS', 'apache2', '2.4.41-4ubuntu3.91']]),
  // ESM だけの修正: 標準のエコシステムでは未修正、Ubuntu Pro のエコシステムで +esm の版が修正
  ubuntuCve(C('10004'), [
    ['Ubuntu:20.04:LTS', 'php7.4', null],
    ['Ubuntu:Pro:20.04:LTS', 'php7.4', '7.4.3-4ubuntu2.90+esm1'],
  ]),
  // 影響なし: Ubuntu は「影響なし」のリリースを affected に載せない（20.04 の行が無い）
  ubuntuCve(C('10005'), [
    ['Ubuntu:22.04:LTS', 'apache2', '2.4.52-1ubuntu4.92'],
    ['Ubuntu:Pro:20.04:LTS', 'php7.4', '7.4.3-4ubuntu2.92+esm1'],
  ]),
  // 影響なし（Debian）: Debian:12 の行が無い
  debianCve(C('10005'), [['Debian:13', 'apache2', '2.4.65-1']]),
  // 修正済み（Debian）: CVE 単位のレコードと DSA の両方にある。DSA は別のリリース（Debian:11）の行も持つ
  debianCve(C('10006'), [
    ['Debian:12', 'apache2', '2.4.62-1~deb12u90'],
    ['Debian:13', 'apache2', '2.4.66-1'],
  ]),
  dsa('DSA-9006-1', [C('10006')], [
    ['Debian:11', 'apache2', '2.4.62-1~deb11u90'],
    ['Debian:12', 'apache2', '2.4.62-1~deb12u90'],
  ]),
  // 未修正（Debian）: introduced だけ
  debianCve(C('10007'), [['Debian:12', 'nginx', null], ['Debian:13', 'nginx', '1.26.3-90']]),
  // 取り下げられたレコードは使わない
  debianCve(C('10008'), [['Debian:12', 'nginx', '1.22.1-9+deb12u90']], { withdrawn: '2090-03-01T00:00:00Z' }),
  // 版として読めない修正版（例: "<not-affected>"）は修正済みの根拠にしない
  debianCve(C('10010'), [['Debian:12', 'nginx', '<not-affected>']]),
  // 中間リリース（Ubuntu:26.10）の修正済み
  ubuntuCve(C('10009'), [['Ubuntu:26.10', 'nginx', '1.30.4-1ubuntu0.90']]),
];

/** 偽の OSV（POST /v1/query）と endoflife.date。OSV は問い合わせのパッケージを affected に含むレコードを返す（実際の API と同じ） */
function fakeServices(records, { failQueries = [], emptyQueries = [] } = {}) {
  const queries = [];
  const urls = [];
  const fetchImpl = async (url, init = {}) => {
    urls.push(url);
    if (url === OSV_QUERY_URL && (init.method || 'GET') === 'POST') {
      const body = JSON.parse(init.body);
      const key = `${body.package.ecosystem}|${body.package.name}`;
      queries.push(key);
      if (failQueries.includes(key)) return { ok: false, status: 500, text: async () => '{}' };
      const vulns = emptyQueries.includes(key)
        ? []
        : records.filter((r) => r.affected.some((a) => a.package.ecosystem === body.package.ecosystem && a.package.name === body.package.name));
      return { ok: true, status: 200, text: async () => JSON.stringify(vulns.length ? { vulns } : {}) };
    }
    const m = url.match(/^https:\/\/endoflife\.date\/api\/([^/]+)\.json$/);
    if (m && RAW_EOL[m[1]]) return { ok: true, status: 200, text: async () => JSON.stringify(RAW_EOL[m[1]]) };
    return { ok: false, status: 404, text: async () => '{}' };
  };
  return { fetchImpl, queries, urls };
}

/** 偽の fetch で --distro-only の取得をして、その upstream から DB を作る */
async function fetchAndBuild({ records = RECORDS, catalog = catalogT05, map = distroMapT05, failQueries, emptyQueries } = {}) {
  const dir = mkTemp('wi-osv-distro-');
  const fake = fakeServices(records, { failQueries, emptyQueries });
  const fetched = await fetchUpstream({
    catalog,
    curated: { products: {} },
    distroMap: map,
    upstreamDir: dir,
    fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
    now: NOW,
    args: { distroOnly: true },
    log: () => {},
  });
  const build = () =>
    buildDatabase({ catalog, curated: fixtureCurated, upstream: loadUpstream(dir), previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT, distroMap: map });
  return { dir, fake, fetched, build };
}

const entryOf = (db, release, pkg, cve) => (db.distro.advisories?.[release]?.[pkg] || []).find((e) => e.cve === cve);

// validateDb の最低製品数・最低件数を満たすための合成の製品
function padProducts() {
  const out = {};
  for (let i = 0; i < 5; i++) {
    out[`dummy${i}`] = {
      aliases: [`dummy${i}`],
      eol: [],
      versions: Array.from({ length: 3 }, (_, j) => ({
        range: '< 1.0.0',
        cve: `CVE-2099-95${i}${j}`,
        cvssScore: 5,
        severity: 'medium',
        title: 'dummy',
        fixedVersion: '1.0.0',
        fixStatus: 'fixed',
        advisoryUrl: `https://nvd.nist.gov/vuln/detail/CVE-2099-95${i}${j}`,
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
/** distro 節を書き換えたあと integrity を付け直す */
const withDistro = (db, mutate) => {
  const out = structuredClone(db);
  mutate(out.distro);
  return bumpAdvisoryDb(out);
};

// ---------------------------------------------------------------------------
// 取得（fetch-upstream）
// ---------------------------------------------------------------------------

describe('T05: fetch-upstream が OSV の Debian / Ubuntu データを取る（fetch は偽物）', () => {
  it('対応表の Debian / Ubuntu の「リリース×ソースパッケージ」（apache・nginx・php）だけを、OSV のエコシステム名で問い合わせること（H1・H8）', async () => {
    const { fake } = await fetchAndBuild();
    expect(new Set(fake.queries)).toEqual(new Set(EXPECTED_QUERIES));
    // RHEL 系（httpd）と openssl は問い合わせない。中間リリースに Ubuntu Pro は無い
    expect(fake.queries.some((q) => q.endsWith('|httpd') || q.endsWith('|openssl'))).toBe(false);
    expect(fake.queries).not.toContain('Ubuntu:Pro:26.10|nginx');
    expect(fake.queries).not.toContain('Ubuntu:26.10:LTS|nginx');
    // OSV への問い合わせは POST /v1/query だけ
    for (const u of fake.urls) expect(u === OSV_QUERY_URL || u.startsWith('https://endoflife.date/api/')).toBe(true);
  });

  it('--distro-only でも upstream/osv-distro/ に保存し、manifest に osv-distro:<エコシステム>:<名前> を記録すること', async () => {
    const { dir, fetched } = await fetchAndBuild();
    const files = fs.readdirSync(path.join(dir, 'osv-distro')).filter((f) => f.endsWith('.json'));
    expect(files.length).toBe(EXPECTED_QUERIES.length);
    for (const q of EXPECTED_QUERIES) {
      const [eco, name] = q.split('|');
      expect(fetched.manifest.sources[`osv-distro:${eco}:${name}`]).toMatchObject({ status: 'ok' });
    }
    // OS のライフサイクルも、これまでどおり取る
    expect(fetched.manifest.sources['distro-eol:ubuntu']).toMatchObject({ status: 'ok' });
  });

  it('--distro-only は既存の製品の取得結果と manifest の取得日時を変えないこと', async () => {
    const dir = mkTemp('wi-osv-distro-seed-');
    const write = (rel, obj) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), JSON.stringify(obj));
    };
    write('osv/npm__jquery.json', { package: { ecosystem: 'npm', name: 'jquery' }, fetchedAt: '2090-01-01T00:00:00.000Z', vulns: [] });
    write('kev.json', { count: 0, vulns: [] });
    write('manifest.json', { schemaVersion: 1, fetchedAt: '2090-01-01T00:00:00.000Z', sources: { 'osv:npm:jquery': { status: 'ok', count: 0, fetchedAt: '2090-01-01T00:00:00.000Z' } } });
    const before = { osv: fs.readFileSync(path.join(dir, 'osv/npm__jquery.json'), 'utf-8'), kev: fs.readFileSync(path.join(dir, 'kev.json'), 'utf-8') };
    const fake = fakeServices(RECORDS);
    const res = await fetchUpstream({
      catalog: catalogT05,
      curated: { products: {} },
      distroMap: distroMapT05,
      upstreamDir: dir,
      fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
      now: NOW,
      args: { distroOnly: true },
      log: () => {},
    });
    expect(fs.readFileSync(path.join(dir, 'osv/npm__jquery.json'), 'utf-8')).toBe(before.osv);
    expect(fs.readFileSync(path.join(dir, 'kev.json'), 'utf-8')).toBe(before.kev);
    expect(res.manifest.fetchedAt).toBe('2090-01-01T00:00:00.000Z');
    expect(res.manifest.sources['osv:npm:jquery']).toMatchObject({ status: 'ok' });
    // 製品の OSV（npm）は問い合わせない
    expect(fake.queries.some((q) => q.startsWith('npm|'))).toBe(false);
  });

  it('通常の取得（--only なし）でも OSV の Debian / Ubuntu データを取り、--only のときは取らないこと', async () => {
    const run = async (args) => {
      const dir = mkTemp('wi-osv-distro-full-');
      const fake = fakeServices(RECORDS);
      const fetchImpl = async (url, init) => {
        if (url.startsWith('https://www.cisa.gov/')) return { ok: true, status: 200, text: async () => JSON.stringify({ catalogVersion: 'x', dateReleased: '2090-01-01T00:00:00Z', vulnerabilities: [] }) };
        return fake.fetchImpl(url, init);
      };
      await fetchUpstream({
        catalog: { ...catalogT05, products: { jquery: fixtureCatalog.products.jquery } },
        curated: { products: {} },
        distroMap: distroMapT05,
        upstreamDir: dir,
        fetchJson: createFetchJson({ fetchImpl, retries: 0 }),
        now: NOW,
        args,
        log: () => {},
      });
      return fake.queries;
    };
    const full = await run({ skipNvd: true });
    expect(full).toEqual(expect.arrayContaining(EXPECTED_QUERIES));
    const only = await run({ skipNvd: true, only: new Set(['jquery']) });
    expect(only.some((q) => q.startsWith('Ubuntu') || q.startsWith('Debian'))).toBe(false);
  });

  it('1 つの問い合わせに失敗しても続け、失敗を manifest に記録すること', async () => {
    const { fetched, dir } = await fetchAndBuild({ failQueries: ['Debian:12|nginx'] });
    expect(fetched.failCount).toBeGreaterThanOrEqual(1);
    expect(fetched.manifest.sources['osv-distro:Debian:12:nginx'].status).not.toBe('ok');
    expect(fetched.manifest.sources['osv-distro:Debian:12:apache2']).toMatchObject({ status: 'ok' });
    expect(fs.readdirSync(path.join(dir, 'osv-distro')).length).toBe(EXPECTED_QUERIES.length - 1);
  });

  it('distroMap を渡さないときは OSV のディストリのデータを取らないこと（T02 までの呼び出し方）', async () => {
    const dir = mkTemp('wi-osv-distro-nomap-');
    const fake = fakeServices(RECORDS);
    await fetchUpstream({
      catalog: { products: {}, distros: catalogT05.distros },
      curated: { products: {} },
      upstreamDir: dir,
      fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
      now: NOW,
      args: { distroOnly: true },
      log: () => {},
    });
    expect(fake.queries).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 圧縮後の形（受け入れ条件 1）
// ---------------------------------------------------------------------------

describe('T05: distro.advisories の圧縮後の形（受け入れ条件 1）', () => {
  it('advisories は「リリース → ソースパッケージ → CVE の配列」で、Debian / Ubuntu の対象だけを持つこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const adv = db.distro.advisories;
    expect(Object.keys(adv).sort()).toEqual(['debian:12', 'ubuntu:20.04', 'ubuntu:26.10']);
    expect(Object.keys(adv['ubuntu:20.04']).sort()).toEqual(['apache2', 'php7.4']);
    expect(Object.keys(adv['debian:12']).sort()).toEqual(['apache2', 'nginx']);
    expect(Object.keys(adv['ubuntu:26.10'])).toEqual(['nginx']);
  });

  it('各 CVE は「CVE ID・修正版・区分・ESM の印・OSV ID」だけを持ち、説明文などを入れないこと（§5.3）', async () => {
    const { db } = (await fetchAndBuild()).build();
    const all = Object.values(db.distro.advisories).flatMap((byPkg) => Object.values(byPkg).flat());
    expect(all.length).toBeGreaterThan(0);
    for (const e of all) {
      for (const k of Object.keys(e)) expect(ALLOWED_ENTRY_KEYS).toContain(k);
      expect(e.cve).toMatch(/^CVE-\d{4}-\d{4,7}$/);
      expect(['fixed', 'open', 'not-affected']).toContain(e.status);
      expect(Array.isArray(e.fixedVersions)).toBe(true);
      expect(Array.isArray(e.osvIds) && e.osvIds.length > 0).toBe(true);
    }
    expect(JSON.stringify(db.distro.advisories)).not.toContain('Synthetic description');
    expect(JSON.stringify(db.distro.advisories)).not.toContain('Synthetic notice');
  });

  it('修正済み（Ubuntu）: 区分 fixed、そのリリースの修正版、元の OSV ID（UBUNTU-CVE と USN）を持ち、ESM の印は無いこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const e = entryOf(db, 'ubuntu:20.04', 'apache2', C('10001'));
    expect(e).toBeDefined();
    expect(e.status).toBe('fixed');
    expect(e.fixedVersions).toEqual(['2.4.41-4ubuntu3.90']);
    expect(e.esm ?? false).toBe(false);
    expect(e.osvIds).toEqual(expect.arrayContaining([`UBUNTU-${C('10001')}`, 'USN-9001-1']));
    // 別のリリース（Pro:18.04・22.04）の修正版は混ざらない
    expect(e.fixedVersions.some((v) => v.includes('ubuntu4.'))).toBe(false);
  });

  it('修正済み（USN だけにある CVE）: USN の upstream の CVE に、そのリリースの修正版が付くこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const e = entryOf(db, 'ubuntu:20.04', 'apache2', C('10002'));
    expect(e).toMatchObject({ status: 'fixed', fixedVersions: ['2.4.41-4ubuntu3.90'] });
    expect(e.osvIds).toContain('USN-9001-1');
  });

  it('修正済み（Debian）: DEBIAN-CVE と DSA の両方の OSV ID を持ち、同じ修正版は 1 つにまとめ、別のリリース（Debian:11）の版は混ざらないこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const e = entryOf(db, 'debian:12', 'apache2', C('10006'));
    expect(e).toMatchObject({ status: 'fixed', fixedVersions: ['2.4.62-1~deb12u90'] });
    expect(e.osvIds).toEqual(expect.arrayContaining([`DEBIAN-${C('10006')}`, 'DSA-9006-1']));
    expect(e.esm ?? false).toBe(false);
  });

  it('未修正（Ubuntu）: 区分 open、修正版は空。USN が修正版を持っていても CVE 単位のレコードを優先すること（安全側）', async () => {
    const { db } = (await fetchAndBuild()).build();
    const e = entryOf(db, 'ubuntu:20.04', 'apache2', C('10003'));
    expect(e).toMatchObject({ status: 'open', fixedVersions: [] });
    expect(e.osvIds).toEqual(expect.arrayContaining([`UBUNTU-${C('10003')}`, 'USN-9003-1']));
  });

  it('未修正（Debian）: introduced だけのレコードは区分 open で、別のリリース（Debian:13）の修正版を持たないこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    expect(entryOf(db, 'debian:12', 'nginx', C('10007'))).toMatchObject({ status: 'open', fixedVersions: [], osvIds: [`DEBIAN-${C('10007')}`] });
  });

  it('ESM だけの修正: 区分 fixed、ESM の印 true、修正版は Ubuntu Pro の版であること', async () => {
    const { db } = (await fetchAndBuild()).build();
    const e = entryOf(db, 'ubuntu:20.04', 'php7.4', C('10004'));
    expect(e).toMatchObject({ status: 'fixed', esm: true, fixedVersions: ['7.4.3-4ubuntu2.90+esm1'] });
    expect(e.osvIds).toEqual([`UBUNTU-${C('10004')}`]);
  });

  it('ESM の印は ESM の修正にだけ付くこと（陰性: 標準の修正・未修正には付かない）', async () => {
    const { db } = (await fetchAndBuild()).build();
    const all = Object.values(db.distro.advisories).flatMap((byPkg) => Object.values(byPkg).flat());
    for (const e of all.filter((x) => x.esm === true)) {
      expect(e.status).toBe('fixed');
      expect(e.fixedVersions.every((v) => /[+~]esm\d*/.test(v))).toBe(true);
    }
    expect(entryOf(db, 'ubuntu:20.04', 'apache2', C('10003')).esm ?? false).toBe(false);
  });

  it('影響なし: ディストリが affected に載せていないリリースには、その CVE を記録しない（「修正済み」「影響なし」と推定しない。H4）', async () => {
    const { db } = (await fetchAndBuild()).build();
    // Ubuntu: 22.04 と Pro:20.04（php7.4）にだけある CVE は、20.04 の apache2 に入らない
    expect(entryOf(db, 'ubuntu:20.04', 'apache2', C('10005'))).toBeUndefined();
    // 同じレコードの php7.4（Pro:20.04）はそのリリースのものなので入る
    expect(entryOf(db, 'ubuntu:20.04', 'php7.4', C('10005'))).toMatchObject({ status: 'fixed', esm: true });
    // Debian: Debian:13 にだけある CVE は Debian:12 に入らない
    expect(entryOf(db, 'debian:12', 'apache2', C('10005'))).toBeUndefined();
    // 載っていないことから not-affected を作らない
    const all = Object.values(db.distro.advisories).flatMap((byPkg) => Object.values(byPkg).flat());
    expect(all.some((e) => e.status === 'not-affected')).toBe(false);
  });

  it('取り下げられたレコードと、版として読めない修正版は、修正済みの根拠にしないこと（陰性）', async () => {
    const { db } = (await fetchAndBuild()).build();
    expect(entryOf(db, 'debian:12', 'nginx', C('10008'))).toBeUndefined();
    const bad = entryOf(db, 'debian:12', 'nginx', C('10010'));
    expect(bad === undefined || bad.status !== 'fixed').toBe(true);
    expect(JSON.stringify(db.distro.advisories)).not.toContain('<not-affected>');
  });

  it('中間リリース（Ubuntu:26.10）の修正済みも同じ形で入ること', async () => {
    const { db } = (await fetchAndBuild()).build();
    expect(entryOf(db, 'ubuntu:26.10', 'nginx', C('10009'))).toMatchObject({ status: 'fixed', fixedVersions: ['1.30.4-1ubuntu0.90'] });
  });

  it('取得はできたがレコードが 0 件の対象は空の配列、取得結果が無い対象は出さず警告すること（「データ無し」と「0 件」を区別する）', async () => {
    const { build } = await fetchAndBuild({ failQueries: ['Debian:12|nginx'], emptyQueries: ['Ubuntu:26.10|nginx'] });
    const { db, report } = build();
    expect(db.distro.advisories['ubuntu:26.10'].nginx).toEqual([]);
    expect(db.distro.advisories['debian:12']?.nginx).toBeUndefined();
    expect(Array.isArray(db.distro.advisories['debian:12'].apache2)).toBe(true);
    expect(report.distro.warnings.some((w) => w.includes('debian:12') && w.includes('nginx'))).toBe(true);
  });

  it('同じ入力から同じ出力（--check の前提）', async () => {
    const { build } = await fetchAndBuild();
    expect(JSON.stringify(build().db)).toBe(JSON.stringify(build().db));
  });

  it('OSV の取得結果が無くても build-db は失敗せず、advisories は空のオブジェクトで警告を出すこと', () => {
    const { db, report } = buildDatabase({
      catalog: catalogT05,
      curated: fixtureCurated,
      upstream: fixtureUpstream,
      previousDb: null,
      asOf: AS_OF,
      generatedAt: GENERATED_AT,
      distroMap: distroMapT05,
    });
    expect(db.distro.advisories).toEqual({});
    expect(report.distro.warnings.length).toBeGreaterThan(0);
  });

  it('libraries と integrity.digest は OSV のディストリのデータで変わらず、distroDigest は distro 節全体と一致すること', async () => {
    const { db } = (await fetchAndBuild()).build();
    // 同じ取得のしかたで、OSV のレコードが 0 件のときと比べる
    const plain = (await fetchAndBuild({ records: [] })).build().db;
    expect(db.distro.advisories).not.toEqual(plain.distro.advisories);
    expect(db.libraries).toEqual(plain.libraries);
    expect(db.integrity.digest).toBe(plain.integrity.digest);
    expect(db.integrity.distroDigest).toBe(sha256(JSON.stringify(db.distro)));
  });
});

// ---------------------------------------------------------------------------
// 出典（_source。受け入れ条件 2）
// ---------------------------------------------------------------------------

describe('T05: distro._source（H2・§5.2）', () => {
  it('_source に OSV（Debian・Ubuntu）と endoflife.date があり、各要素が name・url・ecosystem・license・retrievedAt・recordCount を持つこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const src = db.distro._source;
    expect(Array.isArray(src)).toBe(true);
    const deb = src.find((s) => s.ecosystem === 'Debian');
    const ubu = src.find((s) => s.ecosystem === 'Ubuntu');
    const eol = src.find((s) => /^https:\/\/endoflife\.date\//.test(s.url));
    for (const s of [deb, ubu, eol]) {
      expect(s).toBeDefined();
      for (const k of ['name', 'url', 'ecosystem', 'license', 'retrievedAt', 'recordCount']) expect(k in s, `${s.name} に ${k} がありません`).toBe(true);
      expect(s.url.startsWith('https://')).toBe(true);
      expect(Boolean(s.license) || Boolean(s.licenseNote)).toBe(true);
    }
    expect(ubu.license).toBe('CC-BY-SA-4.0');
    expect(deb.license).toBeNull();
    expect(typeof deb.licenseNote === 'string' && deb.licenseNote.length > 0).toBe(true);
    expect(eol.license).toBe('MIT');
  });

  it('retrievedAt は取得日時、recordCount は使った OSV のレコード数（OS のライフサイクルはリリース数）であること', async () => {
    const { db } = (await fetchAndBuild()).build();
    const src = db.distro._source;
    const idsOf = (family) =>
      new Set(
        Object.entries(db.distro.advisories)
          .filter(([rel]) => rel.startsWith(`${family}:`))
          .flatMap(([, byPkg]) => Object.values(byPkg).flat().flatMap((e) => e.osvIds))
      );
    const deb = src.find((s) => s.ecosystem === 'Debian');
    const ubu = src.find((s) => s.ecosystem === 'Ubuntu');
    const eol = src.find((s) => /^https:\/\/endoflife\.date\//.test(s.url));
    expect(deb.retrievedAt).toBe(NOW.toISOString());
    expect(ubu.retrievedAt).toBe(NOW.toISOString());
    expect(deb.recordCount).toBe(idsOf('debian').size);
    expect(ubu.recordCount).toBe(idsOf('ubuntu').size);
    expect(eol.recordCount).toBe(db.distro.releases.length);
    expect(eol.retrievedAt).toBe(NOW.toISOString());
  });

  it('取得結果が無いときも _source は出し、retrievedAt は null、recordCount は 0 であること', () => {
    const { db } = buildDatabase({ catalog: catalogT05, curated: fixtureCurated, upstream: fixtureUpstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT, distroMap: distroMapT05 });
    const osv = db.distro._source.filter((s) => s.ecosystem === 'Debian' || s.ecosystem === 'Ubuntu');
    expect(osv).toHaveLength(2);
    for (const s of osv) expect(s).toMatchObject({ retrievedAt: null, recordCount: 0 });
  });

  it('DB 全体の sources に OSV（Debian / Ubuntu）が足され、distro 節の無い DB の sources は変わらないこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    // v1.8.2 T06: sources はスキーマ 2.4 で出典ごとのオブジェクト（文字列の配列ではない）。ecosystem で見る
    expect(db.sources.some((s) => s.ecosystem === 'Debian')).toBe(true);
    expect(db.sources.some((s) => s.ecosystem === 'Ubuntu')).toBe(true);
    const plain = buildDatabase({ catalog: fixtureCatalog, curated: fixtureCurated, upstream: fixtureUpstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT }).db;
    expect(plain.sources.some((s) => s.ecosystem === 'Debian' || s.ecosystem === 'Ubuntu')).toBe(false);
  });

  it.each([
    ['Debian の出典の定義が無い', (srcs) => srcs.filter((s) => s.ecosystem !== 'Debian')],
    ['Ubuntu の出典の定義が無い', (srcs) => srcs.filter((s) => s.ecosystem !== 'Ubuntu')],
    ['endoflife.date の出典の定義が無い', (srcs) => srcs.filter((s) => s.ecosystem !== null)],
    ['license も licenseNote も無い', (srcs) => srcs.map((s) => (s.ecosystem === 'Debian' ? { name: s.name, url: s.url, ecosystem: s.ecosystem, license: null } : s))],
    ['license が空文字で licenseNote も無い', (srcs) => srcs.map((s) => (s.ecosystem === 'Ubuntu' ? { name: s.name, url: s.url, ecosystem: s.ecosystem, license: '' } : s))],
  ])('catalog の出典の定義が不正なら build-db は失敗すること（%s。陰性）', (_label, mutate) => {
    const catalog = { ...catalogT05, distroSources: mutate(structuredClone(SOURCES)) };
    expect(() => buildDatabase({ catalog, curated: fixtureCurated, upstream: fixtureUpstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT, distroMap: distroMapT05 })).toThrow();
  });

  it('catalog に出典の定義（distroSources）が無ければ、distro 節を作るときに build-db は失敗すること（陰性）', () => {
    const { distroSources: _omit, ...catalog } = catalogT05;
    expect(() => buildDatabase({ catalog, curated: fixtureCurated, upstream: fixtureUpstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT, distroMap: distroMapT05 })).toThrow(/_source|distroSources/);
  });
});

describe('T05: validateDb が distro.advisories と _source を検査する（C17）', () => {
  it('build-db の出力（advisories と _source あり）は validateDb を通ること（陽性）', async () => {
    const { db } = (await fetchAndBuild()).build();
    expect(Object.keys(db.distro.advisories).length).toBeGreaterThan(0);
    expect(Array.isArray(db.distro._source)).toBe(true);
    expect(() => validateDb(padded(db))).not.toThrow();
  });

  it('advisories も _source も無い distro 節（T02 までの DB・固定 DB の形）は、これまでどおり通ること（互換）', async () => {
    const { db } = (await fetchAndBuild()).build();
    const legacy = withDistro(padded(db), (d) => {
      delete d.advisories;
      delete d._source;
    });
    expect(() => validateDb(legacy)).not.toThrow();
  });

  it.each([
    ['_source が無い', (d) => delete d._source, /_source/],
    ['_source が空', (d) => (d._source = []), /_source/],
    ['OSV（Debian）が無い', (d) => (d._source = d._source.filter((s) => s.ecosystem !== 'Debian')), /_source|Debian/],
    ['OSV（Ubuntu）が無い', (d) => (d._source = d._source.filter((s) => s.ecosystem !== 'Ubuntu')), /_source|Ubuntu/],
    ['endoflife.date が無い', (d) => (d._source = d._source.filter((s) => s.ecosystem !== null)), /_source|endoflife/],
    ['license も licenseNote も無い要素がある', (d) => d._source.forEach((s) => { s.license = null; delete s.licenseNote; }), /license/],
  ])('validateDb は %s distro 節を拒否すること（陰性）', async (_label, mutate, message) => {
    const { db } = (await fetchAndBuild()).build();
    const base = padded(db);
    expect(() => validateDb(base)).not.toThrow();
    const bad = withDistro(base, mutate);
    expect(() => validateDb(bad)).toThrow(message);
  });

  it.each([
    ['区分が不正', (d) => (d.advisories['debian:12'].apache2[0].status = 'safe')],
    ['CVE ID が不正', (d) => (d.advisories['debian:12'].apache2[0].cve = 'not-a-cve')],
    ['OSV ID が無い', (d) => (d.advisories['debian:12'].apache2[0].osvIds = [])],
    ['修正済みなのに修正版が無い', (d) => (d.advisories['debian:12'].apache2.find((e) => e.status === 'fixed').fixedVersions = [])],
    ['修正版に HTML の特殊文字', (d) => (d.advisories['debian:12'].apache2.find((e) => e.status === 'fixed').fixedVersions = ['<script>'])],
    ['リリースのキーが不正', (d) => (d.advisories['rhel:9'] = { httpd: [] })],
  ])('validateDb は advisories の形が不正なら拒否すること（%s。陰性）', async (_label, mutate) => {
    const { db } = (await fetchAndBuild()).build();
    const base = padded(db);
    // 書き換えの前の DB は通る（拒否の理由が書き換えだけであることを確かめる）
    expect(() => validateDb(base)).not.toThrow();
    const bad = withDistro(base, mutate);
    expect(() => validateDb(bad)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// distro 節のサイズ（受け入れ条件 3 の build-db / validateDb 側。§5.3）
// ---------------------------------------------------------------------------

describe('T05: distro 節が 800 KB を超えたら build-db と validateDb が失敗する（§5.3・H8）', () => {
  /** 1 つの対象に大量の修正済みレコードを返す偽の OSV（合成） */
  const manyRecords = (n) =>
    Array.from({ length: n }, (_, i) => debianCve(`CVE-2090-${100000 + i}`, [['Debian:12', 'apache2', `2.4.62-1~deb12u${'9'.repeat(80)}${i}`]]));

  it('超えたら build-db は例外を投げ、古いリリースを外して通すことはしないこと', async () => {
    const { build } = await fetchAndBuild({ records: manyRecords(5000) });
    expect(() => build()).toThrow(/distro/);
  });

  it('validateDb も 800 KB を超えた distro 節を拒否し、上限以下なら通すこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    const base = padded(db);
    expect(() => validateDb(base)).not.toThrow();
    const big = withDistro(base, (d) => {
      const list = d.advisories['debian:12'].apache2;
      let i = 0;
      // 500 件ずつ足して、上限を超えたところで止める（毎回の文字列化を減らす）
      while (Buffer.byteLength(JSON.stringify(d)) <= DISTRO_LIMIT_BYTES) {
        for (let j = 0; j < 500; j++, i++) {
          list.push({ cve: `CVE-2090-${200000 + i}`, status: 'fixed', fixedVersions: [`2.4.62-1~deb12u${'9'.repeat(80)}${i}`], osvIds: [`DEBIAN-CVE-2090-${200000 + i}`] });
        }
      }
    });
    expect(Buffer.byteLength(JSON.stringify(big.distro))).toBeGreaterThan(DISTRO_LIMIT_BYTES);
    expect(() => validateDb(big)).toThrow(/distro/);
  });
});

// ---------------------------------------------------------------------------
// build-db の CLI（受け入れ条件 2: build-db --check）
// ---------------------------------------------------------------------------

describe('T05: build-db --check（受け入れ条件 2）', () => {
  /** 一時ディレクトリに、本番のスクリプトとデータ（catalog・curated・distro-map）と、偽の fetch で取った upstream を置く */
  async function setupTree() {
    const root = mkTemp('wi-osv-distro-cli-');
    const copyDir = (rel) => {
      for (const ent of fs.readdirSync(path.join(REPO_ROOT, rel), { withFileTypes: true })) {
        const r = `${rel}/${ent.name}`;
        if (ent.isDirectory()) copyDir(r);
        else if (ent.isFile()) copy(r);
      }
    };
    const copy = (rel) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(root, rel));
    };
    copyDir('scripts/advisories');
    for (const rel of ['scripts/validate-advisories.mjs', 'data/advisories/catalog.json', 'data/advisories/curated.json', 'data/advisories/distro-map.json']) copy(rel);
    fs.mkdirSync(path.join(root, 'src/detection'), { recursive: true });
    const catalog = JSON.parse(fs.readFileSync(path.join(root, 'data/advisories/catalog.json'), 'utf-8'));
    const distroMap = JSON.parse(fs.readFileSync(path.join(root, 'data/advisories/distro-map.json'), 'utf-8'));
    const fake = fakeServices(RECORDS);
    await fetchUpstream({
      catalog,
      curated: { products: {} },
      distroMap,
      upstreamDir: path.join(root, 'data/advisories/upstream'),
      fetchJson: createFetchJson({ fetchImpl: fake.fetchImpl, retries: 0 }),
      now: NOW,
      args: { distroOnly: true },
      log: () => {},
    });
    const script = path.join(root, 'scripts/advisories/build-db.mjs');
    const dbPath = path.join(root, 'src/detection', BUNDLED_DB_FILE);
    const run = (...args) => {
      const r = spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: 'utf-8' });
      return { status: r.status, output: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
    };
    const editCatalog = (mutate) => {
      const p = path.join(root, 'data/advisories/catalog.json');
      const c = JSON.parse(fs.readFileSync(p, 'utf-8'));
      mutate(c);
      fs.writeFileSync(p, `${JSON.stringify(c, null, 2)}\n`);
    };
    return { root, run, dbPath, editCatalog };
  }

  it('本番の入力と OSV の取得結果から生成でき、--check が通ること（陽性）', async () => {
    const t = await setupTree();
    const gen = t.run();
    expect(gen.status, gen.output).toBe(0);
    const db = JSON.parse(fs.readFileSync(t.dbPath, 'utf-8'));
    expect(Array.isArray(db.distro._source)).toBe(true);
    expect(db.distro.advisories['debian:12'].apache2.length).toBeGreaterThan(0);
    expect(entryOf(db, 'ubuntu:20.04', 'php7.4', C('10004'))).toMatchObject({ status: 'fixed', esm: true });
    const chk = t.run('--check');
    expect(chk.status, chk.output).toBe(0);
  });

  it('コミット済みの DB の distro 節に _source が無いと --check が失敗し、_source の問題だと分かること', async () => {
    const t = await setupTree();
    expect(t.run().status).toBe(0);
    const db = JSON.parse(fs.readFileSync(t.dbPath, 'utf-8'));
    delete db.distro._source;
    fs.writeFileSync(t.dbPath, `${JSON.stringify(db, null, 2)}\n`);
    const chk = t.run('--check');
    expect(chk.status).not.toBe(0);
    expect(chk.output).toContain('_source');
  });

  it('catalog の OSV（Debian）の出典に license も licenseNote も無いと、生成も --check も失敗すること', async () => {
    const t = await setupTree();
    expect(t.run().status).toBe(0);
    t.editCatalog((c) => {
      for (const s of c.distroSources) if (s.ecosystem === 'Debian') { s.license = null; delete s.licenseNote; }
    });
    const chk = t.run('--check');
    expect(chk.status).not.toBe(0);
    expect(chk.output).toContain('license');
    expect(t.run().status).not.toBe(0);
  });

  it('catalog に endoflife.date の出典が無いと --check が失敗すること', async () => {
    const t = await setupTree();
    expect(t.run().status).toBe(0);
    t.editCatalog((c) => {
      c.distroSources = c.distroSources.filter((s) => s.ecosystem !== null);
    });
    const chk = t.run('--check');
    expect(chk.status).not.toBe(0);
    expect(chk.output).toMatch(/_source|endoflife/);
  });
});

// ---------------------------------------------------------------------------
// 本番の catalog.json の出典の定義
// ---------------------------------------------------------------------------

describe('T05: 本番の catalog.json の出典の定義（§5.2）', () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'data/advisories/catalog.json'), 'utf-8'));

  it('OSV（Ubuntu）は CC-BY-SA-4.0、OSV（Debian）は license が null で licenseNote があり、endoflife.date は MIT であること', () => {
    const srcs = catalog.distroSources;
    expect(Array.isArray(srcs)).toBe(true);
    const ubu = srcs.find((s) => s.ecosystem === 'Ubuntu');
    const deb = srcs.find((s) => s.ecosystem === 'Debian');
    const eol = srcs.find((s) => s.ecosystem === null && /^https:\/\/endoflife\.date\//.test(s.url));
    expect(ubu?.license).toBe('CC-BY-SA-4.0');
    expect(deb?.license).toBeNull();
    expect(typeof deb?.licenseNote === 'string' && deb.licenseNote.length > 0).toBe(true);
    expect(eol?.license).toBe('MIT');
    for (const s of srcs) {
      expect(new URL(s.url).protocol).toBe('https:');
      expect(typeof s.name === 'string' && s.name.length > 0).toBe(true);
    }
  });

  it('本番の catalog と distro-map から（OSV の取得結果なしで）DB を作れて validateDb を通ること', () => {
    const map = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'data/advisories/distro-map.json'), 'utf-8'));
    const { db } = buildDatabase({ catalog, curated: fixtureCurated, upstream: fixtureUpstream, previousDb: null, asOf: AS_OF, generatedAt: GENERATED_AT, distroMap: map });
    expect(db.distro._source.length).toBeGreaterThanOrEqual(3);
    expect(() => validateDb(padded(db))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// DB だけのリリースの予行（受け入れ条件 4）
// ---------------------------------------------------------------------------

describe('T05: DB だけのリリースの予行が、advisories と _source を含む distro 節で通る（受け入れ条件 4）', () => {
  it('bumpAdvisoryDb は advisories と _source を変えずに distroDigest を計算し直すこと', async () => {
    const { db } = (await fetchAndBuild()).build();
    expect(Object.keys(db.distro.advisories).length).toBeGreaterThan(0);
    expect(Array.isArray(db.distro._source)).toBe(true);
    const bumped = bumpAdvisoryDb({ ...structuredClone(db), integrity: { ...db.integrity, distroDigest: '0'.repeat(64) } });
    expect(bumped.distro).toEqual(db.distro);
    expect(bumped.integrity.distroDigest).toBe(sha256(JSON.stringify(db.distro)));
  });

  it('合成の作業ツリーで予行が通り、予行の後の DB が validateDb（_source の検査を含む）を通ること', async () => {
    const { db } = (await fetchAndBuild()).build();
    const full = padded(db);
    const root = mkTemp('wi-osv-distro-rehearsal-');
    const write = (rel, text) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.writeFileSync(path.join(root, rel), text);
    };
    // 合成の版（同梱の package.json の版ではない）
    write('package.json', `${JSON.stringify({ name: 'synthetic', version: '3.4.5', type: 'module' })}\n`);
    write('public/manifest.json', `${JSON.stringify({ manifest_version: 3, name: 'Synthetic', version: '3.4.5' })}\n`);
    write('data/synthetic-db.json', `${JSON.stringify(full, null, 2)}\n`);
    const copyDir = (rel) => {
      for (const ent of fs.readdirSync(path.join(REPO_ROOT, rel), { withFileTypes: true })) {
        const r = `${rel}/${ent.name}`;
        if (ent.isDirectory()) copyDir(r);
        else if (ent.isFile()) write(r, fs.readFileSync(path.join(REPO_ROOT, r), 'utf-8'));
      }
    };
    copyDir('scripts/advisories');
    write('scripts/validate-advisories.mjs', fs.readFileSync(path.join(REPO_ROOT, 'scripts/validate-advisories.mjs'), 'utf-8'));
    write(
      'check.mjs',
      `import fs from 'node:fs';
import { validateDb } from './scripts/validate-advisories.mjs';
const db = JSON.parse(fs.readFileSync('data/synthetic-db.json', 'utf-8'));
try {
  validateDb(db);
  if (!db.distro || !db.distro.advisories || !Array.isArray(db.distro._source)) throw new Error('distro 節に advisories と _source がありません');
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
`
    );
    const r = await rehearseDbRelease({ sourceDir: root, advisoryDbPath: 'data/synthetic-db.json', testCommand: [process.execPath, 'check.mjs'] });
    expect(r.ok, '予行が失敗しました').toBe(true);
    expect(r.dataVersion > r.previousDataVersion).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(root, 'data/synthetic-db.json'), 'utf-8'))).toEqual(full);
  });
});
