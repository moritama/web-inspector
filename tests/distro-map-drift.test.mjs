/**
 * v1.8.1 T04: 対応表（data/advisories/distro-map.json）の週次の突き合わせ（§5.4・H3）
 *
 * - scripts/advisories/check-distro-map.mjs が、Ubuntu は Launchpad の API、Debian は sources.debian.org の API で
 *   各リリースの現在の版を取り、対応表に無い上流版が公開されていれば「ずれ」、一致すれば「なし」、取得に失敗すれば「未確認」にする。
 * - 対応表は書き換えない。結果は build-report.json の distroMapDrift に入れ、pr-plan.mjs がボット PR の本文に「対応表のずれ」の節を作る。
 * - ネットワークには出ない。取得関数（createFetchJson）に偽の fetch を渡す。偽の応答の形は設計メモ（docs/dev/v1.8.1/design/T04.md の「外部の事実」）のとおり。
 *   CLI のテストは、Node.js の --import で globalThis.fetch を偽物に差し替えてから実行する。
 * - パッケージの版は合成（実在の版ではないことが分かるよう、上流版に 9 を多く含めた）。日付は 2090 年代の合成。
 */

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { checkDistroMap, runDistroMapCheck } from '../scripts/advisories/check-distro-map.mjs';
import { createFetchJson } from '../scripts/advisories/lib/http.mjs';
import { planPullRequest, renderPrBody } from '../scripts/advisories/pr-plan.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NOW = new Date('2090-03-04T05:06:07.000Z');
const API_HOSTS = new Set(['api.launchpad.net', 'sources.debian.org']);

const tempDirs = [];
/** 一時ディレクトリ（macOS の /tmp は /private/tmp へのリンクなので、実パスに解決してから使う） */
const mkTemp = (prefix) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
};
afterEach(() => {
  while (tempDirs.length > 0) fs.rmSync(tempDirs.pop(), { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 合成の対応表
// ---------------------------------------------------------------------------

const LP_EVIDENCE = (pkg, series) =>
  `https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=${pkg}&exact_match=true&distro_series=https://api.launchpad.net/1.0/ubuntu/${series}`;

const entry = (o) => ({ verifiedAt: '2090-01-02', ...o });

const UBUNTU_NGINX = entry({
  family: 'ubuntu', release: 'ubuntu:22.04', codename: 'jammy', product: 'nginx',
  upstreamVersions: ['1.18.0'], sourcePackage: 'nginx', evidenceUrl: LP_EVIDENCE('nginx', 'jammy'),
});
const UBUNTU_OPENSSL = entry({
  family: 'ubuntu', release: 'ubuntu:18.04', codename: 'bionic', product: 'openssl',
  upstreamVersions: ['1.1.0g', '1.1.1'], sourcePackage: 'openssl', evidenceUrl: LP_EVIDENCE('openssl', 'bionic'),
});
const DEBIAN_APACHE = entry({
  family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'apache',
  upstreamVersions: ['2.4.57', '2.4.59'], sourcePackage: 'apache2', evidenceUrl: 'https://sources.debian.org/api/src/apache2/',
});
const DEBIAN_APACHE_TRIXIE = entry({
  family: 'debian', release: 'debian:13', codename: 'trixie', product: 'apache',
  upstreamVersions: ['2.4.65'], sourcePackage: 'apache2', evidenceUrl: 'https://sources.debian.org/api/src/apache2/',
});
const RHEL_APACHE = entry({
  family: 'rhel', release: 'rhel:9', codename: null, product: 'apache',
  upstreamVersions: ['2.4.57'], sourcePackage: 'httpd', evidenceUrl: 'https://dl.rockylinux.org/vault/rocky/',
});

const mapOf = (...entries) => ({ _comment: '合成', schemaVersion: 1, entries });

// ---------------------------------------------------------------------------
// 偽の API（応答の形は Launchpad の getPublishedSources と sources.debian.org の /api/src/<pkg>/ に合わせる）
// ---------------------------------------------------------------------------

/** Launchpad の source_package_publishing_history の 1 件（実際の応答の項目のうち、判定に関わるものと主なもの） */
const lpEntry = (pkg, series, version, { status = 'Published', pocket = 'Updates' } = {}) => ({
  self_link: `https://api.launchpad.net/1.0/ubuntu/+archive/primary/+sourcepub/9${version.length}`,
  resource_type_link: 'https://api.launchpad.net/1.0/#source_package_publishing_history',
  display_name: `${pkg} ${version} in ${series}`,
  component_name: 'main',
  section_name: 'web',
  status,
  distro_series_link: `https://api.launchpad.net/1.0/ubuntu/${series}`,
  date_published: '2090-01-01T00:00:00+00:00',
  pocket,
  archive_link: 'https://api.launchpad.net/1.0/ubuntu/+archive/primary',
  source_package_name: pkg,
  source_package_version: version,
});

/** sources.debian.org の /api/src/<pkg>/ の応答 */
const debSrc = (pkg, versions) => ({
  package: pkg,
  path: pkg,
  pathl: [[pkg, `/src/${pkg}`]],
  suite: '',
  type: 'package',
  versions: versions.map(([version, suites]) => ({ area: 'main', suites, version })),
});

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

/**
 * 偽の fetch。
 * - launchpad: { '<series>/<pkg>': entries[] | Response を返す関数 | { pages: entries[][] } }
 * - debian: { '<pkg>': body | Response を返す関数 }
 * 一覧に無い URL は 404。呼ばれた URL は calls に残る。
 */
function fakeApis({ launchpad = {}, debian = {} } = {}) {
  const calls = [];
  const fetchImpl = async (input) => {
    const url = new URL(String(input));
    calls.push(url.href);
    if (url.hostname === 'api.launchpad.net' && url.pathname.endsWith('/ubuntu/+archive/primary') && url.searchParams.get('ws.op') === 'getPublishedSources') {
      const series = (url.searchParams.get('distro_series') || '').replace(/\/+$/, '').split('/').pop();
      const pkg = url.searchParams.get('source_name');
      const def = launchpad[`${series}/${pkg}`];
      if (def === undefined) return json(404, { error: 'not found' });
      if (typeof def === 'function') return def(url);
      if (def && Array.isArray(def.pages)) {
        const start = Number(url.searchParams.get('ws.start') || '0');
        const page = def.pages[start] ?? [];
        const body = { start, total_size: def.pages.flat().length, entries: page };
        if (start + 1 < def.pages.length) {
          const next = new URL(url.href);
          next.searchParams.set('ws.start', String(start + 1));
          next.searchParams.set('ws.size', '1');
          body.next_collection_link = next.href;
        }
        return json(200, body);
      }
      return json(200, { start: 0, total_size: def.length, entries: def });
    }
    if (url.hostname === 'sources.debian.org') {
      const m = /^\/api\/src\/([^/]+)\/?$/.exec(url.pathname);
      const def = m ? debian[m[1]] : undefined;
      // sources.debian.org は、無いパッケージにも HTTP 200 で {"error":404} を返す
      if (def === undefined) return json(200, { error: 404 });
      if (typeof def === 'function') return def(url);
      return json(200, def);
    }
    return json(404, { error: 'not found' });
  };
  return { calls, fetchJson: createFetchJson({ fetchImpl, retries: 0 }) };
}

const itemOf = (result, release, product) => result.items.find((i) => i.release === release && i.product === product);

// ---------------------------------------------------------------------------
// 受け入れ条件 1: 「ずれ」「なし」「未確認」
// ---------------------------------------------------------------------------

describe('T04: checkDistroMap — Ubuntu（Launchpad）', () => {
  it('対応表に無い上流版が公開されていれば「ずれ」（drift）になり、その上流版を報告すること（陽性）', async () => {
    const { fetchJson } = fakeApis({
      launchpad: {
        'jammy/nginx': [
          lpEntry('nginx', 'jammy', '1.99.9-0ubuntu1', { pocket: 'Updates' }),
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' }),
        ],
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const item = itemOf(result, 'ubuntu:22.04', 'nginx');
    expect(item, 'ubuntu:22.04 の nginx の結果がありません').toBeDefined();
    expect(item.status).toBe('drift');
    expect(item.sourcePackage).toBe('nginx');
    expect(item.unlistedUpstreamVersions).toContain('1.99.9');
    expect(item.unlistedUpstreamVersions).not.toContain('1.18.0');
    expect(result.status).toBe('drift');
  });

  it('公開中の版の上流版がすべて対応表にあれば「なし」（none）になること（陰性）', async () => {
    const { fetchJson } = fakeApis({
      launchpad: {
        'jammy/nginx': [
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14.99', { pocket: 'Updates' }),
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14.99', { pocket: 'Security' }),
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' }),
        ],
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const item = itemOf(result, 'ubuntu:22.04', 'nginx');
    expect(item.status).toBe('none');
    expect(item.unlistedUpstreamVersions).toEqual([]);
    expect(result.status).toBe('none');
  });

  it('Proposed・Backports のポケットと、Published 以外の状態（Superseded など）の版は数えないこと（陰性）', async () => {
    const { fetchJson } = fakeApis({
      launchpad: {
        'jammy/nginx': [
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' }),
          lpEntry('nginx', 'jammy', '1.97.9-0ubuntu1', { pocket: 'Proposed' }),
          lpEntry('nginx', 'jammy', '1.96.9-0ubuntu1~22.04.1', { pocket: 'Backports' }),
          lpEntry('nginx', 'jammy', '1.95.9-0ubuntu1', { status: 'Superseded', pocket: 'Updates' }),
          lpEntry('nginx', 'jammy', '1.94.9-0ubuntu1', { status: 'Deleted', pocket: 'Security' }),
          lpEntry('nginx', 'jammy', '1.93.9-0ubuntu1', { status: 'Pending', pocket: 'Updates' }),
        ],
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    expect(itemOf(result, 'ubuntu:22.04', 'nginx').status).toBe('none');
  });

  it('Ubuntu の版から上流版を取り出すとき、epoch・ディストリの revision・「~18.04.N」の印を外すこと（陰性）', async () => {
    const { fetchJson } = fakeApis({
      launchpad: {
        'bionic/openssl': [
          lpEntry('openssl', 'bionic', '1.1.0g-2ubuntu4', { pocket: 'Release' }),
          lpEntry('openssl', 'bionic', '1.1.1-1ubuntu2.1~18.04.99', { pocket: 'Security' }),
          lpEntry('openssl', 'bionic', '1:1.1.1-1ubuntu2.1~18.04.99', { pocket: 'Updates' }),
        ],
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_OPENSSL), fetchJson, now: NOW });
    expect(itemOf(result, 'ubuntu:18.04', 'openssl').status).toBe('none');
  });

  it('応答が複数のページに分かれているときは、次のページ（next_collection_link）も見ること（陽性）', async () => {
    const { fetchJson } = fakeApis({
      launchpad: {
        'jammy/nginx': {
          pages: [
            [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })],
            [lpEntry('nginx', 'jammy', '1.98.9-0ubuntu1', { pocket: 'Security' })],
          ],
        },
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const item = itemOf(result, 'ubuntu:22.04', 'nginx');
    expect(item.status).toBe('drift');
    expect(item.unlistedUpstreamVersions).toContain('1.98.9');
  });

  it('Launchpad の問い合わせは、getPublishedSources をソースパッケージ名とリリースのコード名（distro_series）で行うこと', async () => {
    const { fetchJson, calls } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
    });
    await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const lp = calls.map((c) => new URL(c)).filter((u) => u.hostname === 'api.launchpad.net');
    expect(lp.length).toBeGreaterThan(0);
    expect(lp[0].searchParams.get('ws.op')).toBe('getPublishedSources');
    expect(lp[0].searchParams.get('source_name')).toBe('nginx');
    expect(lp[0].searchParams.get('distro_series')).toMatch(/\/ubuntu\/jammy\/?$/);
  });
});

describe('T04: checkDistroMap — Debian（sources.debian.org）', () => {
  it('そのリリース（コード名の suite）に対応表に無い上流版があれば「ずれ」（drift）になること（陽性）', async () => {
    const { fetchJson } = fakeApis({
      debian: {
        apache2: debSrc('apache2', [
          ['2.4.99-1', ['sid']],
          ['2.4.99-1~deb12u1', ['bookworm']],
          ['2.4.65-2', ['trixie']],
        ]),
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    const item = itemOf(result, 'debian:12', 'apache');
    expect(item.status).toBe('drift');
    expect(item.sourcePackage).toBe('apache2');
    expect(item.unlistedUpstreamVersions).toContain('2.4.99');
    expect(result.status).toBe('drift');
  });

  it('そのリリースの版が対応表にあれば、ほかのリリース（sid・trixie）に新しい版があっても「なし」（none）になること（陰性）', async () => {
    const { fetchJson } = fakeApis({
      debian: {
        apache2: debSrc('apache2', [
          ['2.4.99-1', ['forky', 'sid']],
          ['2.4.98-1~deb13u1', ['trixie']],
          ['2.4.59-1~deb12u9', ['bookworm']],
          ['2.4.38-3+deb10u99', ['buster']],
        ]),
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('none');
    expect(result.status).toBe('none');
  });

  it('proposed-updates と backports の suite の版は数えないこと（陰性）', async () => {
    const { fetchJson } = fakeApis({
      debian: {
        apache2: debSrc('apache2', [
          ['2.4.97-1~deb12u1', ['bookworm-proposed-updates']],
          ['2.4.96-1~bpo12+1', ['bookworm-backports']],
          ['2.4.57-3~deb12u9', ['bookworm']],
        ]),
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('none');
  });

  it('同じ版が複数の suite に載っている要素（suites が配列）も扱えること（陽性）', async () => {
    const { fetchJson } = fakeApis({
      debian: { apache2: debSrc('apache2', [['2.4.99-1~deb12u1', ['bookworm', 'bookworm-proposed-updates']]]) },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('drift');
  });

  it('Debian の版の epoch と「+dfsg」の付いた上流版も、上流版の数字の部分で比べること（陰性）', async () => {
    const { fetchJson } = fakeApis({
      debian: { apache2: debSrc('apache2', [['1:2.4.59+dfsg-1~deb12u9', ['bookworm']]]) },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('none');
  });

  it('同じソースパッケージを複数のリリースで使っていても、リリースごとに判定すること', async () => {
    const { fetchJson } = fakeApis({
      debian: {
        apache2: debSrc('apache2', [
          ['2.4.59-1~deb12u9', ['bookworm']],
          ['2.4.99-1~deb13u1', ['trixie']],
        ]),
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE, DEBIAN_APACHE_TRIXIE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('none');
    expect(itemOf(result, 'debian:13', 'apache').status).toBe('drift');
    expect(itemOf(result, 'debian:13', 'apache').unlistedUpstreamVersions).toContain('2.4.99');
  });
});

describe('T04: checkDistroMap — 取得に失敗したら「未確認」', () => {
  const cases = [
    ['HTTP 500', () => json(500, { error: 'boom' })],
    ['HTTP 404', () => json(404, { error: 'not found' })],
    ['ネットワークのエラー', () => { throw new TypeError('fetch failed'); }],
    ['JSON でない応答', () => new Response('<html>maintenance</html>', { status: 200 })],
    ['entries が配列でない応答', () => json(200, { start: 0, total_size: 0 })],
    ['公開中（Published）の版が 1 件も無い応答', () => json(200, { start: 0, total_size: 0, entries: [] })],
  ];

  it.each(cases)('Launchpad: %s なら「未確認」（unchecked）になり、例外を投げないこと', async (_label, respond) => {
    const { fetchJson } = fakeApis({ launchpad: { 'jammy/nginx': respond } });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const item = itemOf(result, 'ubuntu:22.04', 'nginx');
    expect(item.status).toBe('unchecked');
    expect(item.unlistedUpstreamVersions).toEqual([]);
    expect(result.status).toBe('unchecked');
  });

  const debianCases = [
    ['HTTP 200 の {"error":404}（無いパッケージ）', () => json(200, { error: 404 })],
    ['HTTP 503', () => json(503, { error: 'unavailable' })],
    ['versions が配列でない応答', () => json(200, { package: 'apache2', versions: null })],
    ['そのリリースの suite が 1 件も無い応答', () => json(200, debSrc('apache2', [['2.4.99-1', ['sid']]]))],
  ];

  it.each(debianCases)('Debian: %s なら「未確認」（unchecked）になること', async (_label, respond) => {
    const { fetchJson } = fakeApis({ debian: { apache2: respond } });
    const result = await checkDistroMap({ distroMap: mapOf(DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('unchecked');
    expect(result.status).toBe('unchecked');
  });

  it('未確認の項目には、理由（error）が空でない文字列で付くこと', async () => {
    const { fetchJson } = fakeApis({ launchpad: { 'jammy/nginx': () => json(500, {}) } });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const item = itemOf(result, 'ubuntu:22.04', 'nginx');
    expect(typeof item.error).toBe('string');
    expect(item.error.length).toBeGreaterThan(0);
  });

  it('1 つの取得が失敗しても、ほかの項目の突き合わせを続けること', async () => {
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': () => json(500, {}) },
      debian: { apache2: debSrc('apache2', [['2.4.99-1~deb12u1', ['bookworm']]]) },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, DEBIAN_APACHE), fetchJson, now: NOW });
    expect(itemOf(result, 'ubuntu:22.04', 'nginx').status).toBe('unchecked');
    expect(itemOf(result, 'debian:12', 'apache').status).toBe('drift');
  });
});

describe('T04: checkDistroMap — 全体の結果', () => {
  const ok = fakeApis({
    launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
    debian: { apache2: debSrc('apache2', [['2.4.57-3~deb12u1', ['bookworm']]]) },
  });

  it('すべて一致すれば全体は「なし」で、件数（counts）が項目の数と合うこと', async () => {
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, DEBIAN_APACHE), fetchJson: ok.fetchJson, now: NOW });
    expect(result.status).toBe('none');
    expect(result.counts).toEqual({ drift: 0, none: 2, unchecked: 0, outOfScope: 0 });
    expect(result.items).toHaveLength(2);
  });

  it('ずれと未確認が混ざれば全体は「ずれ」、なしと未確認が混ざれば全体は「未確認」（なしと断定しない）こと', async () => {
    const mixed1 = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.99.9-0ubuntu1', { pocket: 'Updates' })] },
      debian: { apache2: () => json(503, {}) },
    });
    const r1 = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, DEBIAN_APACHE), fetchJson: mixed1.fetchJson, now: NOW });
    expect(r1.status).toBe('drift');
    expect(r1.counts).toEqual({ drift: 1, none: 0, unchecked: 1, outOfScope: 0 });

    const mixed2 = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
      debian: { apache2: () => json(503, {}) },
    });
    const r2 = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, DEBIAN_APACHE), fetchJson: mixed2.fetchJson, now: NOW });
    expect(r2.status).toBe('unchecked');
    expect(r2.counts).toEqual({ drift: 0, none: 1, unchecked: 1, outOfScope: 0 });
  });

  it('RHEL 系の項目は突き合わせの対象外で、問い合わせをせず、結果の項目にも照合の件数（ずれ・一致・未確認）にも入れないこと', async () => {
    const { fetchJson, calls } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, RHEL_APACHE), fetchJson, now: NOW });
    expect(result.items.map((i) => i.release)).toEqual(['ubuntu:22.04']);
    expect(result.status).toBe('none');
    expect(result.counts.drift + result.counts.none + result.counts.unchecked).toBe(1);
    expect(calls.every((c) => API_HOSTS.has(new URL(c).hostname))).toBe(true);
  });

  it('照合の手段が無い項目は「対象外」として件数と family 別の内訳に残し、「全件確認した」ように見せないこと', async () => {
    const ROCKY_NGINX = entry({
      family: 'rocky', release: 'rocky:9', codename: null, product: 'nginx',
      upstreamVersions: ['1.20.1'], sourcePackage: 'nginx', evidenceUrl: 'https://dl.rockylinux.org/vault/rocky/',
    });
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
    });
    const result = await checkDistroMap({
      distroMap: mapOf(UBUNTU_NGINX, RHEL_APACHE, ROCKY_NGINX),
      fetchJson,
      now: NOW,
    });
    expect(result.counts.outOfScope).toBe(2);
    expect(result.outOfScopeByFamily).toEqual({ rhel: 1, rocky: 1 });
    // 対象外は全体の結果を変えない（照合できた分だけで判定する）
    expect(result.status).toBe('none');
    expect(result.items.every((i) => i.family === 'ubuntu' || i.family === 'debian')).toBe(true);
  });

  it('対象外が 1 件も無ければ outOfScope は 0 で、内訳は空であること', async () => {
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson: ok.fetchJson, now: NOW });
    expect(result.counts.outOfScope).toBe(0);
    expect(result.outOfScopeByFamily).toEqual({});
  });

  it('問い合わせ先は Launchpad と sources.debian.org の API だけであること', async () => {
    const { fetchJson, calls } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
      debian: { apache2: debSrc('apache2', [['2.4.57-3~deb12u1', ['bookworm']]]) },
    });
    await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX, DEBIAN_APACHE, RHEL_APACHE), fetchJson, now: NOW });
    const hosts = new Set(calls.map((c) => new URL(c).hostname));
    expect([...hosts].sort()).toEqual([...API_HOSTS].sort());
  });

  it('checkedAt は渡した now の ISO 8601 の文字列で、結果は JSON にそのまま書けること', async () => {
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson: ok.fetchJson, now: NOW });
    expect(result.checkedAt).toBe(NOW.toISOString());
    expect(JSON.parse(JSON.stringify(result))).toEqual(result);
  });

  it('渡した対応表（オブジェクト）を書き換えないこと', async () => {
    const map = mapOf(UBUNTU_NGINX, DEBIAN_APACHE, RHEL_APACHE);
    const before = structuredClone(map);
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.99.9-0ubuntu1', { pocket: 'Updates' })] },
      debian: { apache2: debSrc('apache2', [['2.4.99-1~deb12u1', ['bookworm']]]) },
    });
    await checkDistroMap({ distroMap: map, fetchJson, now: NOW });
    expect(map).toEqual(before);
  });

  it('応答の版に版として不正な文字（< > ` | 空白など）があれば、その版は使わず結果にも残さないこと', async () => {
    const evil = '1.99.9-0ubuntu1<img src=x onerror=alert(1)>`|';
    const { fetchJson } = fakeApis({
      launchpad: {
        'jammy/nginx': [
          lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' }),
          lpEntry('nginx', 'jammy', evil, { pocket: 'Updates' }),
        ],
      },
    });
    const result = await checkDistroMap({ distroMap: mapOf(UBUNTU_NGINX), fetchJson, now: NOW });
    const text = JSON.stringify(result);
    expect(text).not.toContain('<img');
    expect(text).not.toContain('onerror');
    expect(itemOf(result, 'ubuntu:22.04', 'nginx').status).toBe('none');
  });
});

// ---------------------------------------------------------------------------
// 受け入れ条件 2: 対応表のファイルを書き換えない。結果は build-report.json の distroMapDrift
// ---------------------------------------------------------------------------

describe('T04: runDistroMapCheck — ファイルの読み書き', () => {
  const setup = () => {
    const dir = mkTemp('wi-t04-run-');
    const mapPath = path.join(dir, 'distro-map.json');
    const reportPath = path.join(dir, 'build-report.json');
    // 実際のファイルと同じく、1 項目 1 行の手書きの書式（stableStringify と違う書式）にしておく
    const mapText = `{\n  "_comment": "合成",\n  "schemaVersion": 1,\n  "entries": [\n${[UBUNTU_NGINX, DEBIAN_APACHE, RHEL_APACHE].map((e) => `    ${JSON.stringify(e)}`).join(',\n')}\n  ]\n}\n`;
    fs.writeFileSync(mapPath, mapText, 'utf-8');
    const report = { asOf: '2090-03-01', products: { synthetic: { curated: 1, auto: 0 } }, drift: [], excluded: [], skippedSummary: {}, staleSources: [] };
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf-8');
    return { dir, mapPath, reportPath, mapText, report };
  };

  it('ずれがあっても対応表のファイルを 1 バイトも変えず、build-report.json の distroMapDrift に結果を入れること', async () => {
    const { mapPath, reportPath, mapText, report } = setup();
    const statBefore = fs.statSync(mapPath);
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.99.9-0ubuntu1', { pocket: 'Updates' })] },
      debian: { apache2: debSrc('apache2', [['2.4.99-1~deb12u1', ['bookworm']]]) },
    });
    const result = await runDistroMapCheck({ mapPath, reportPath, fetchJson, now: NOW });
    expect(result.status).toBe('drift');
    expect(fs.readFileSync(mapPath, 'utf-8')).toBe(mapText);
    expect(fs.statSync(mapPath).mtimeMs).toBe(statBefore.mtimeMs);

    const written = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    expect(written.distroMapDrift).toEqual(JSON.parse(JSON.stringify(result)));
    expect(written.distroMapDrift.status).toBe('drift');
    // build-db が書いたほかの項目はそのまま残す
    for (const [k, v] of Object.entries(report)) expect(written[k]).toEqual(v);
  });

  it('取得にすべて失敗しても例外を投げず、distroMapDrift に「未確認」を記録し、対応表は変えないこと', async () => {
    const { mapPath, reportPath, mapText } = setup();
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': () => json(500, {}) },
      debian: { apache2: () => json(500, {}) },
    });
    const result = await runDistroMapCheck({ mapPath, reportPath, fetchJson, now: NOW });
    expect(result.status).toBe('unchecked');
    expect(JSON.parse(fs.readFileSync(reportPath, 'utf-8')).distroMapDrift.status).toBe('unchecked');
    expect(fs.readFileSync(mapPath, 'utf-8')).toBe(mapText);
  });

  it('前回の distroMapDrift は今回の結果で置き換えること', async () => {
    const { mapPath, reportPath } = setup();
    const prev = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    prev.distroMapDrift = { checkedAt: '2089-01-01T00:00:00.000Z', status: 'drift', counts: { drift: 9, none: 0, unchecked: 0 }, items: [] };
    fs.writeFileSync(reportPath, JSON.stringify(prev), 'utf-8');
    const { fetchJson } = fakeApis({
      launchpad: { 'jammy/nginx': [lpEntry('nginx', 'jammy', '1.18.0-6ubuntu14', { pocket: 'Release' })] },
      debian: { apache2: debSrc('apache2', [['2.4.57-3~deb12u1', ['bookworm']]]) },
    });
    await runDistroMapCheck({ mapPath, reportPath, fetchJson, now: NOW });
    const written = JSON.parse(fs.readFileSync(reportPath, 'utf-8')).distroMapDrift;
    expect(written.status).toBe('none');
    expect(written.checkedAt).toBe(NOW.toISOString());
  });

  it('対応表のファイルが読めないときも例外を投げず「未確認」を記録すること', async () => {
    const { dir, reportPath } = setup();
    const { fetchJson } = fakeApis({});
    const result = await runDistroMapCheck({ mapPath: path.join(dir, 'missing.json'), reportPath, fetchJson, now: NOW });
    expect(result.status).toBe('unchecked');
    expect(JSON.parse(fs.readFileSync(reportPath, 'utf-8')).distroMapDrift.status).toBe('unchecked');
  });
});

describe('T04: check-distro-map.mjs の CLI', () => {
  /** 一時ディレクトリにスクリプトと対応表をコピーする（PATHS はスクリプトの場所から決まる） */
  const copyTree = () => {
    const root = mkTemp('wi-t04-cli-');
    const copy = (rel) => {
      fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
      fs.copyFileSync(path.join(REPO_ROOT, rel), path.join(root, rel));
    };
    for (const f of fs.readdirSync(path.join(REPO_ROOT, 'scripts/advisories/lib'))) copy(`scripts/advisories/lib/${f}`);
    for (const rel of ['scripts/advisories/check-distro-map.mjs', 'data/advisories/distro-map.json']) copy(rel);
    return root;
  };

  /** globalThis.fetch を「HTTP 404 を返し、URL を記録する」偽物に差し替える preload（ネットワークに出ない） */
  const writeFailingFetchPreload = (dir) => {
    const log = path.join(dir, 'fetch-calls.log');
    const preload = path.join(dir, 'fake-fetch.mjs');
    fs.writeFileSync(
      preload,
      [
        "import fs from 'node:fs';",
        `const LOG = ${JSON.stringify(log)};`,
        'globalThis.fetch = async (input) => {',
        "  fs.appendFileSync(LOG, String(input) + '\\n');",
        "  return new Response(JSON.stringify({ error: 'offline test' }), { status: 404, headers: { 'Content-Type': 'application/json' } });",
        '};',
        '',
      ].join('\n'),
      'utf-8'
    );
    return { preload, log };
  };

  it('API にすべて失敗しても終了コード 0 で終わり、「未確認」を build-report.json に記録し、対応表を変えないこと', () => {
    const root = copyTree();
    const reportPath = path.join(root, 'data/advisories/build-report.json');
    const report = { asOf: '2090-03-01', products: {}, drift: [], excluded: [], skippedSummary: {}, staleSources: [] };
    fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf-8');
    const mapPath = path.join(root, 'data/advisories/distro-map.json');
    const mapBytes = fs.readFileSync(mapPath);
    const { preload, log } = writeFailingFetchPreload(root);

    const script = fs.realpathSync(path.join(root, 'scripts/advisories/check-distro-map.mjs'));
    const r = spawnSync(process.execPath, ['--import', pathToFileURL(preload).href, script], {
      cwd: root,
      encoding: 'utf-8',
      timeout: 90_000,
      env: { ...process.env, GITHUB_OUTPUT: '', GITHUB_STEP_SUMMARY: '' },
    });
    expect(r.status, `${r.stdout}\n${r.stderr}`).toBe(0);

    expect(Buffer.compare(fs.readFileSync(mapPath), mapBytes)).toBe(0);
    const written = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
    expect(written.distroMapDrift?.status).toBe('unchecked');
    for (const [k, v] of Object.entries(report)) expect(written[k]).toEqual(v);

    // 本物の対応表の Ubuntu・Debian の項目がすべて結果に入り、RHEL 系は入らない
    const map = JSON.parse(mapBytes.toString('utf-8'));
    const targets = map.entries.filter((e) => e.family === 'ubuntu' || e.family === 'debian');
    expect(written.distroMapDrift.items).toHaveLength(targets.length);
    expect(written.distroMapDrift.items.every((i) => i.status === 'unchecked')).toBe(true);

    // 問い合わせ先は Launchpad と sources.debian.org の API だけで、両方に問い合わせている
    const hosts = new Set(fs.readFileSync(log, 'utf-8').trim().split('\n').filter(Boolean).map((u) => new URL(u).hostname));
    expect([...hosts].sort()).toEqual([...API_HOSTS].sort());
  }, 120_000);
});

// ---------------------------------------------------------------------------
// pr-plan.mjs: ボット PR の本文の「対応表のずれ」の節
// ---------------------------------------------------------------------------

const DRIFT_RESULT = {
  checkedAt: NOW.toISOString(),
  status: 'drift',
  counts: { drift: 1, none: 1, unchecked: 1 },
  items: [
    { family: 'ubuntu', release: 'ubuntu:22.04', codename: 'jammy', product: 'nginx', sourcePackage: 'nginx', status: 'drift', mapUpstreamVersions: ['1.18.0'], publishedVersions: ['1.99.9-0ubuntu1'], unlistedUpstreamVersions: ['1.99.9'], sourceUrl: LP_EVIDENCE('nginx', 'jammy') },
    { family: 'debian', release: 'debian:12', codename: 'bookworm', product: 'apache', sourcePackage: 'apache2', status: 'none', mapUpstreamVersions: ['2.4.57'], publishedVersions: ['2.4.57-3~deb12u1'], unlistedUpstreamVersions: [], sourceUrl: 'https://sources.debian.org/api/src/apache2/' },
    { family: 'debian', release: 'debian:13', codename: 'trixie', product: 'php', sourcePackage: 'php8.4', status: 'unchecked', mapUpstreamVersions: ['8.4.11'], publishedVersions: [], unlistedUpstreamVersions: [], sourceUrl: 'https://sources.debian.org/api/src/php8.4/', error: 'HTTP 503' },
  ],
};
const NONE_RESULT = {
  checkedAt: NOW.toISOString(),
  status: 'none',
  counts: { drift: 0, none: 1, unchecked: 0 },
  items: [{ ...DRIFT_RESULT.items[1] }],
};
const UNCHECKED_RESULT = {
  checkedAt: NOW.toISOString(),
  status: 'unchecked',
  counts: { drift: 0, none: 0, unchecked: 1 },
  items: [{ ...DRIFT_RESULT.items[2] }],
};

const basePlan = {
  classification: 'minor',
  version: '0.0.0.1',
  testsPassed: true,
  autoMerge: true,
  hasAppToken: true,
  diffMarkdown: '## 脆弱性DB 自動更新\n',
};

describe('T04: pr-plan — ボット PR の本文の「対応表のずれ」の節', () => {
  it('ずれがあれば、本文に「対応表のずれ」の節を作り、リリース・ソースパッケージ・対応表に無い上流版を載せること（陽性）', () => {
    const plan = planPullRequest({ ...basePlan, distroMapDrift: DRIFT_RESULT });
    expect(plan.body).toContain('## 脆弱性DB 自動更新');
    expect(plan.body).toContain('対応表のずれ');
    expect(plan.body).toContain('ubuntu:22.04');
    expect(plan.body).toContain('nginx');
    expect(plan.body).toContain('1.99.9');
  });

  it('ずれと一緒に未確認の項目があれば、未確認のリリースも「未確認」として載せること', () => {
    const plan = planPullRequest({ ...basePlan, distroMapDrift: DRIFT_RESULT });
    expect(plan.body).toContain('未確認');
    expect(plan.body).toContain('debian:13');
  });

  it('対象外があれば、件数と family 別の内訳を節に出し、人が確かめる旨を書くこと', () => {
    const withOutOfScope = {
      ...DRIFT_RESULT,
      counts: { ...DRIFT_RESULT.counts, outOfScope: 34 },
      outOfScopeByFamily: { rhel: 12, rocky: 11, almalinux: 8, centos: 3 },
    };
    const plan = planPullRequest({ ...basePlan, distroMapDrift: withOutOfScope });
    const section = plan.body.slice(plan.body.indexOf('対応表のずれ'));
    expect(section).toContain('対象外 34 件');
    expect(section).toContain('rhel 12 件');
    expect(section).toContain('centos 3 件');
    expect(section).toContain('verifiedAt');
  });

  it('対象外が 0 件なら、対象外の行は出さないこと', () => {
    const plan = planPullRequest({ ...basePlan, distroMapDrift: NONE_RESULT });
    const section = plan.body.slice(plan.body.indexOf('対応表のずれ'));
    expect(section).not.toContain('対象外');
  });

  it('ずれが無ければ、節に「なし」と書き、上流版の一覧は載せないこと（陰性）', () => {
    const plan = planPullRequest({ ...basePlan, distroMapDrift: NONE_RESULT });
    const section = plan.body.slice(plan.body.indexOf('対応表のずれ'));
    expect(plan.body).toContain('対応表のずれ');
    expect(section).toContain('なし');
    expect(section).not.toContain('1.99.9');
    expect(section).not.toContain('ubuntu:22.04');
  });

  it('取得に失敗していれば、節に「未確認」と書き、「なし」と断定しないこと', () => {
    const plan = planPullRequest({ ...basePlan, distroMapDrift: UNCHECKED_RESULT });
    const section = plan.body.slice(plan.body.indexOf('対応表のずれ'));
    expect(plan.body).toContain('対応表のずれ');
    expect(section).toContain('未確認');
    expect(section).toContain('debian:13');
    expect(section).not.toContain('なし');
  });

  it('distroMapDrift を渡さなければ、本文は従来どおり（節を作らない）こと（陰性・互換）', () => {
    const plan = planPullRequest({ ...basePlan });
    expect(plan.body).not.toContain('対応表のずれ');
    expect(plan.body).toBe(renderPrBody(basePlan.diffMarkdown, { testsPassed: true, failedTests: [] }));
  });

  it('ずれがあっても PR を止めないこと（PR の作成・ラベル・自動マージ・ジョブの成否は、ずれが無いときと同じ）', () => {
    for (const drift of [DRIFT_RESULT, UNCHECKED_RESULT]) {
      const withDrift = planPullRequest({ ...basePlan, distroMapDrift: drift });
      const without = planPullRequest({ ...basePlan });
      expect(withDrift.shouldCreatePr).toBe(true);
      expect(withDrift.shouldCreatePr).toBe(without.shouldCreatePr);
      expect(withDrift.labels).toEqual(without.labels);
      expect(withDrift.shouldAutoMerge).toBe(without.shouldAutoMerge);
      expect(withDrift.shouldFailJob).toBe(false);
    }
  });

  it('テストが失敗したときも、失敗したテストの節と「対応表のずれ」の節の両方を載せること', () => {
    const plan = planPullRequest({ ...basePlan, testsPassed: false, failedTests: ['suite > failing test'], distroMapDrift: DRIFT_RESULT });
    expect(plan.body).toContain('suite > failing test');
    expect(plan.body).toContain('対応表のずれ');
    expect(plan.body).toContain('1.99.9');
  });
});

describe('T04: pr-plan の CLI（--build-report）', () => {
  const PR_PLAN = fs.realpathSync(path.join(REPO_ROOT, 'scripts/advisories/pr-plan.mjs'));

  const run = (dir, extraArgs) => {
    const diffMd = path.join(dir, 'db-diff.md');
    const outBody = path.join(dir, 'pr-body.md');
    fs.writeFileSync(diffMd, '## 脆弱性DB 自動更新\n', 'utf-8');
    execFileSync(
      process.execPath,
      [PR_PLAN, '--classification', 'minor', '--version', '0.0.0.1', '--tests-passed', 'true', '--diff-md', diffMd, '--out-body', outBody, ...extraArgs],
      { cwd: dir, encoding: 'utf-8', stdio: 'pipe', env: { ...process.env, GITHUB_OUTPUT: '' } }
    );
    return fs.readFileSync(outBody, 'utf-8');
  };

  it('--build-report で渡した build-report.json の distroMapDrift から「対応表のずれ」の節を作ること', () => {
    const dir = mkTemp('wi-t04-prplan-');
    const reportPath = path.join(dir, 'build-report.json');
    fs.writeFileSync(reportPath, JSON.stringify({ asOf: '2090-03-01', products: {}, distroMapDrift: DRIFT_RESULT }), 'utf-8');
    const body = run(dir, ['--build-report', reportPath]);
    expect(body).toContain('対応表のずれ');
    expect(body).toContain('ubuntu:22.04');
    expect(body).toContain('1.99.9');
  });

  it('build-report.json に distroMapDrift が無い・ファイルが無いときは、節を作らずに成功すること（陰性）', () => {
    const dir = mkTemp('wi-t04-prplan-');
    const reportPath = path.join(dir, 'build-report.json');
    fs.writeFileSync(reportPath, JSON.stringify({ asOf: '2090-03-01', products: {} }), 'utf-8');
    expect(run(dir, ['--build-report', reportPath])).not.toContain('対応表のずれ');
    expect(run(dir, ['--build-report', path.join(dir, 'missing.json')])).not.toContain('対応表のずれ');
  });
});
