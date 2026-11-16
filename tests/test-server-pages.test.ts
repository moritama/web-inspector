// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * v1.8.1 T07: test-server の手動確認用ページの受け入れテスト (tests/test-server-pages.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.1/design/T07.md
 *
 * サーバーを起動せず（listen しない）、test-server/server.mjs が export する
 * リクエストハンドラーに偽の req / res を渡して、各ページが想定のヘッダーと本文を返すことを確かめる。
 *
 * - WAF 確認画面: cf-mitigated: challenge と /cdn-cgi/challenge-platform/、x-amzn-waf-action
 * - 外部 CDN の SRI: integrity なしとありの script / stylesheet（判定は属性で行われる）
 * - ディストリのバナー: Ubuntu（Apache ＋ PHP、パッケージ版あり）、Debian（~debNuM）、RHEL 系、
 *   deb.sury.org、~bpo、対応表に無い版。版の文字列は distro-map.json から取る（ページに直接書かない）
 * - HTTPS 専用ヘッダー（COOP・COEP）を HTTP で返すページ
 * - 新しいページが起動時の一覧にある
 */

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { detectInterstitial } from '../src/detection/interstitial';
import { inferDistroFromHeaders } from '../src/detection/distro-inference';
import { checkHttpHeaders } from '../src/security/headers';
import { checkSubresourceIntegrity } from '../src/security/sri';
import type { AdvisoryDistroSection, DistroInference, SriResourceItem } from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';

const SERVER_PATH = path.join(REPO_ROOT, 'test-server', 'server.mjs');
const DISTRO_MAP_PATH = path.join(REPO_ROOT, 'data', 'advisories', 'distro-map.json');
const PORT = 3000;
const ORIGIN = `http://localhost:${PORT}`;

/** 設計メモ「実装の方針」で決めた新しいページのパス */
const PAGE = {
  cloudflare: '/waf-cloudflare-challenge',
  aws: '/waf-aws-captcha',
  sri: '/sri-cdn',
  ubuntu: '/distro-ubuntu-apache-php',
  debian: '/distro-debian-deb',
  rhel: '/distro-rhel',
  sury: '/distro-sury',
  bpo: '/distro-debian-bpo',
  unmapped: '/distro-unmapped',
  httpsOnly: '/https-only-headers',
} as const;
const NEW_PATHS: readonly string[] = Object.values(PAGE);

/** 既存のページ（一覧から消えていないことの確認用） */
const EXISTING_PATHS = ['/insecure-cookie', '/loose-csp', '/legacy-lib', '/distro-apache', '/spa-settle'];

// ---------------------------------------------------------------------------
// 偽の req / res
// ---------------------------------------------------------------------------

interface DistroMapLike {
  entries: Array<{
    family: string;
    release: string;
    codename: string | null;
    product: string;
    upstreamVersions: string[];
    sourcePackage: string;
    verifiedAt: string;
    evidenceUrl: string;
  }>;
}

type Handler = (req: unknown, res: unknown) => unknown;

interface ServerModule {
  createRequestHandler: (options?: { distroMap?: DistroMapLike }) => Handler;
  TEST_PAGES: ReadonlyArray<{ path: string; label: string }>;
  getStartupLines: (port: number) => string[];
}

interface FakeResponse {
  statusCode: number;
  headers: Record<string, string[]>;
  body: string;
}

function normalizeHeaders(raw: Record<string, unknown>): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (v === undefined || v === null) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.map(String) : [String(v)];
  }
  return out;
}

/** ハンドラーに偽の GET リクエストを渡し、res.end が呼ばれるまで待つ */
function request(handler: Handler, pathname: string): Promise<FakeResponse> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, unknown> = {};
    let body = '';
    let done = false;
    const timer = setTimeout(() => {
      if (!done) reject(new Error(`${pathname}: res.end が呼ばれませんでした`));
    }, 2000);
    const res = {
      statusCode: 200,
      headersSent: false,
      setHeader(name: string, value: unknown) {
        headers[name.toLowerCase()] = value;
        return res;
      },
      getHeader(name: string) {
        return headers[name.toLowerCase()];
      },
      hasHeader(name: string) {
        return name.toLowerCase() in headers;
      },
      removeHeader(name: string) {
        delete headers[name.toLowerCase()];
      },
      writeHead(code: number, a?: unknown, b?: unknown) {
        res.statusCode = code;
        const h = (a && typeof a === 'object' ? a : b) as Record<string, unknown> | undefined;
        if (h && typeof h === 'object') {
          for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = v;
        }
        res.headersSent = true;
        return res;
      },
      write(chunk: unknown) {
        if (chunk !== undefined && chunk !== null) body += String(chunk);
        return true;
      },
      end(chunk?: unknown) {
        if (chunk !== undefined && chunk !== null && typeof chunk !== 'function') body += String(chunk);
        done = true;
        clearTimeout(timer);
        resolve({ statusCode: res.statusCode, headers: normalizeHeaders(headers), body });
        return res;
      },
    };
    const req = { url: pathname, method: 'GET', headers: { host: `localhost:${PORT}` } };
    try {
      handler(req, res);
    } catch (e) {
      clearTimeout(timer);
      reject(e);
    }
  });
}

const header = (r: FakeResponse, name: string): string => (r.headers[name.toLowerCase()] || []).join(', ');

function infer(r: FakeResponse, map: DistroMapLike): Partial<Record<string, DistroInference>> {
  const section = { releases: [], map: map.entries } as unknown as AdvisoryDistroSection;
  return inferDistroFromHeaders(
    { server: r.headers['server'], 'x-powered-by': r.headers['x-powered-by'] },
    section
  );
}

/** バナーに出ている「製品/版」の版だけを取り出す */
function bannerVersions(value: string): Array<{ product: string; version: string }> {
  const out: Array<{ product: string; version: string }> = [];
  const re = /(Apache|nginx|PHP|OpenSSL)\/(\d+(?:\.\d+)+[a-z]?)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value)) !== null) out.push({ product: m[1].toLowerCase(), version: m[2] });
  return out;
}

function mapVersions(map: DistroMapLike, family: string, product: string, release?: string): string[] {
  return map.entries
    .filter((e) => e.family === family && e.product === product && (!release || e.release === release))
    .flatMap((e) => e.upstreamVersions);
}

// ---------------------------------------------------------------------------
// 読み込み（listen しない）
// ---------------------------------------------------------------------------

const realMap = JSON.parse(fs.readFileSync(DISTRO_MAP_PATH, 'utf-8')) as DistroMapLike;

/** 版の出どころを確かめるための合成の対応表（実在しない版・リリース） */
const SYNTHETIC_MAP: DistroMapLike = {
  entries: [
    { family: 'ubuntu', release: 'ubuntu:90.04', codename: 'synthu', product: 'apache', upstreamVersions: ['9.4.71'], sourcePackage: 'apache2', verifiedAt: '', evidenceUrl: 'https://distro.example.test/u-apache' },
    { family: 'ubuntu', release: 'ubuntu:90.04', codename: 'synthu', product: 'php', upstreamVersions: ['9.7.13'], sourcePackage: 'php9.7', verifiedAt: '', evidenceUrl: 'https://distro.example.test/u-php' },
    { family: 'debian', release: 'debian:91', codename: 'synthd', product: 'apache', upstreamVersions: ['9.4.72'], sourcePackage: 'apache2', verifiedAt: '', evidenceUrl: 'https://distro.example.test/d-apache' },
    { family: 'debian', release: 'debian:91', codename: 'synthd', product: 'php', upstreamVersions: ['9.7.14'], sourcePackage: 'php9.7', verifiedAt: '', evidenceUrl: 'https://distro.example.test/d-php' },
    { family: 'rhel', release: 'rhel:92', codename: null, product: 'apache', upstreamVersions: ['9.4.73'], sourcePackage: 'httpd', verifiedAt: '', evidenceUrl: 'https://distro.example.test/r-apache' },
  ],
};
const SYNTHETIC_VERSIONS = SYNTHETIC_MAP.entries.flatMap((e) => e.upstreamVersions);

let mod: ServerModule;
let listenSpy: { mockRestore: () => void };
let logSpy: { mockRestore: () => void };

beforeAll(async () => {
  // 読み込みでサーバーが起動しても実際のポートを開かないようにしたうえで、起動しないことを確かめる
  listenSpy = vi.spyOn(net.Server.prototype, 'listen').mockImplementation(function (this: net.Server) {
    return this;
  });
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
  mod = (await import(pathToFileURL(fs.realpathSync(SERVER_PATH)).href)) as ServerModule;
});

afterAll(() => {
  listenSpy.mockRestore();
  logSpy.mockRestore();
});

describe('T07: test-server はサーバーを起動せずに読み込める', () => {
  it('import しただけでは listen しない（node test-server/server.mjs で実行したときだけ起動する）', () => {
    expect(listenSpy).not.toHaveBeenCalled();
  });

  it('createRequestHandler・TEST_PAGES・getStartupLines を export している', () => {
    expect(typeof mod.createRequestHandler).toBe('function');
    expect(Array.isArray(mod.TEST_PAGES)).toBe(true);
    expect(typeof mod.getStartupLines).toBe('function');
  });
});

describe('T07: 新しいページが起動時の一覧にある', () => {
  it.each(NEW_PATHS.map((p) => [p]))('%s が TEST_PAGES にあり、ラベルが付いている', (p) => {
    const page = mod.TEST_PAGES.find((x) => x.path === p);
    expect(page, `${p} が一覧にありません`).toBeDefined();
    expect(page!.label.trim().length).toBeGreaterThan(0);
  });

  it.each(NEW_PATHS.map((p) => [p]))('%s の URL が起動時に表示する行にある', (p) => {
    const lines = mod.getStartupLines(PORT);
    expect(lines.some((l) => l.includes(`${ORIGIN}${p}`))).toBe(true);
  });

  it('起動時の行は TEST_PAGES のすべてのページを含み、既存のページも一覧から消えていない', () => {
    const lines = mod.getStartupLines(PORT);
    for (const page of mod.TEST_PAGES) {
      expect(lines.some((l) => l.includes(`${ORIGIN}${page.path}`)), page.path).toBe(true);
    }
    for (const p of EXISTING_PATHS) {
      expect(lines.some((l) => l.includes(`${ORIGIN}${p}`)), p).toBe(true);
    }
  });

  it('ポート番号を引数どおりに使う', () => {
    const lines = mod.getStartupLines(4321);
    expect(lines.some((l) => l.includes(`http://localhost:4321${PAGE.sri}`))).toBe(true);
  });
});

describe('T07: 新しいページはそれぞれ専用の HTML を返す（既定のページに落ちない）', () => {
  it.each(NEW_PATHS.map((p) => [p]))('%s は HTML を返し、本文に自分のパスを書いている', async (p) => {
    const r = await request(mod.createRequestHandler(), p);
    expect(r.statusCode).toBeLessThan(500);
    expect(header(r, 'content-type')).toMatch(/text\/html/i);
    expect(r.body).toContain(p);
  });
});

// ---------------------------------------------------------------------------
// WAF 確認画面
// ---------------------------------------------------------------------------

describe('T07: WAF 確認画面のページ', () => {
  it('Cloudflare: cf-mitigated: challenge を返し、/cdn-cgi/challenge-platform/ のスクリプトを含み、確認画面として判定される', async () => {
    const r = await request(mod.createRequestHandler(), PAGE.cloudflare);
    expect(r.headers['cf-mitigated']).toEqual(['challenge']);
    const doc = new DOMParser().parseFromString(r.body, 'text/html');
    const srcs = Array.from(doc.querySelectorAll('script[src]')).map((s) => s.getAttribute('src') || '');
    expect(srcs.some((s) => new URL(s, `${ORIGIN}${PAGE.cloudflare}`).pathname.startsWith('/cdn-cgi/challenge-platform/'))).toBe(true);
    expect(detectInterstitial(undefined, r.headers)?.vendor).toBe('Cloudflare');
  });

  it('AWS WAF: x-amzn-waf-action（captcha か challenge）を返し、確認画面として判定される', async () => {
    const r = await request(mod.createRequestHandler(), PAGE.aws);
    const action = header(r, 'x-amzn-waf-action').toLowerCase();
    expect(['captcha', 'challenge']).toContain(action);
    expect(detectInterstitial(undefined, r.headers)?.vendor).toBe('AWS WAF');
  });

  it.each(['/', PAGE.sri, PAGE.ubuntu])('陰性: %s は WAF のヘッダーを返さず、確認画面と判定されない', async (p) => {
    const r = await request(mod.createRequestHandler(), p);
    expect(r.headers['cf-mitigated']).toBeUndefined();
    expect(r.headers['x-amzn-waf-action']).toBeUndefined();
    expect(detectInterstitial(undefined, r.headers)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 外部 CDN の SRI
// ---------------------------------------------------------------------------

describe('T07: 外部 CDN の SRI のページ', () => {
  async function sriResources(): Promise<{ items: SriResourceItem[]; pageUrl: string }> {
    const pageUrl = `${ORIGIN}${PAGE.sri}`;
    const r = await request(mod.createRequestHandler(), PAGE.sri);
    const doc = new DOMParser().parseFromString(r.body, 'text/html');
    const items: SriResourceItem[] = [];
    for (const el of Array.from(doc.querySelectorAll('script[src]'))) {
      items.push({
        kind: 'script',
        url: new URL(el.getAttribute('src') || '', pageUrl).href,
        hasIntegrity: (el.getAttribute('integrity') || '').trim() !== '',
      });
    }
    for (const el of Array.from(doc.querySelectorAll('link[href]'))) {
      const rel = (el.getAttribute('rel') || '').toLowerCase().split(/\s+/);
      if (!rel.includes('stylesheet')) continue;
      items.push({
        kind: 'stylesheet',
        url: new URL(el.getAttribute('href') || '', pageUrl).href,
        hasIntegrity: (el.getAttribute('integrity') || '').trim() !== '',
      });
    }
    return { items, pageUrl };
  }

  it('integrity なしとありの script / stylesheet をそれぞれ 1 つ以上含み、すべて外部の https の URL', async () => {
    const { items } = await sriResources();
    const external = items.filter((i) => new URL(i.url).hostname !== 'localhost');
    for (const kind of ['script', 'stylesheet'] as const) {
      expect(external.some((i) => i.kind === kind && i.hasIntegrity), `${kind} integrity あり`).toBe(true);
      expect(external.some((i) => i.kind === kind && !i.hasIntegrity), `${kind} integrity なし`).toBe(true);
    }
    for (const i of external) {
      expect(i.url.startsWith('https://'), i.url).toBe(true);
    }
  });

  it('integrity の値は SRI の書式（sha256 / sha384 / sha512 と base64）', async () => {
    const r = await request(mod.createRequestHandler(), PAGE.sri);
    const doc = new DOMParser().parseFromString(r.body, 'text/html');
    const values = Array.from(doc.querySelectorAll('[integrity]')).map((e) => e.getAttribute('integrity') || '');
    expect(values.length).toBeGreaterThan(0);
    for (const v of values) {
      expect(v).toMatch(/^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$/);
    }
  });

  it('SRI の診断で、integrity なしの URL だけが SEC-SRI-01 に出る（integrity ありの URL は出ない）', async () => {
    const { items, pageUrl } = await sriResources();
    const checks = checkSubresourceIntegrity(pageUrl, items);
    const sri01 = checks.find((c) => c.checkId === 'SEC-SRI-01');
    expect(sri01).toBeDefined();
    const external = items.filter((i) => new URL(i.url).hostname !== 'localhost');
    for (const i of external.filter((x) => !x.hasIntegrity)) {
      expect(sri01!.observed, i.url).toContain(i.url.split(/[?#]/)[0]);
    }
    for (const i of external.filter((x) => x.hasIntegrity)) {
      expect(sri01!.observed, i.url).not.toContain(i.url.split(/[?#]/)[0]);
    }
  });
});

// ---------------------------------------------------------------------------
// ディストリのバナー（版は distro-map.json から）
// ---------------------------------------------------------------------------

describe('T07: ディストリのバナーのページ（同梱の対応表 distro-map.json の版を使う）', () => {
  const handler = (): Handler => mod.createRequestHandler();

  it('Ubuntu（Apache ＋ PHP、パッケージ版あり）: どちらも ubuntu と推定され、PHP はパッケージ版を持つ', async () => {
    const r = await request(handler(), PAGE.ubuntu);
    expect(header(r, 'server')).toMatch(/^Apache\/\S+ \(Ubuntu\)/);
    expect(header(r, 'x-powered-by')).toMatch(/^PHP\/\d+(?:\.\d+)+-\S*ubuntu\d/);
    for (const { product, version } of [...bannerVersions(header(r, 'server')), ...bannerVersions(header(r, 'x-powered-by'))]) {
      expect(mapVersions(realMap, 'ubuntu', product), `${product}/${version}`).toContain(version);
    }
    const inf = infer(r, realMap);
    for (const product of ['apache', 'php']) {
      expect(inf[product]?.family, product).toBe('ubuntu');
      expect(inf[product]?.thirdParty, product).toBeUndefined();
      expect(inf[product]?.confidence, product).not.toBe('none');
      expect(inf[product]?.candidates.length, product).toBeGreaterThan(0);
    }
  });

  it('Debian（~debNuM）: PHP のパッケージ版の印からリリースが決まり（high）、版はそのリリースの対応表にある', async () => {
    const r = await request(handler(), PAGE.debian);
    const xpb = header(r, 'x-powered-by');
    const m = xpb.match(/~deb(\d+)u\d+/);
    expect(m, xpb).not.toBeNull();
    const release = `debian:${m![1]}`;
    const php = bannerVersions(xpb).find((v) => v.product === 'php');
    expect(php).toBeDefined();
    expect(mapVersions(realMap, 'debian', 'php', release)).toContain(php!.version);
    const inf = infer(r, realMap);
    expect(inf.php?.family).toBe('debian');
    expect(inf.php?.release).toBe(release);
    expect(inf.php?.confidence).toBe('high');
    expect(inf.php?.thirdParty).toBeUndefined();
  });

  it('RHEL 系: Server の括弧内の OS 名から rhel と推定され、候補は rhel のリリースだけ', async () => {
    const r = await request(handler(), PAGE.rhel);
    expect(header(r, 'server')).toContain('(Red Hat Enterprise Linux)');
    const apache = bannerVersions(header(r, 'server')).find((v) => v.product === 'apache');
    expect(apache).toBeDefined();
    expect(mapVersions(realMap, 'rhel', 'apache')).toContain(apache!.version);
    const inf = infer(r, realMap);
    expect(inf.apache?.family).toBe('rhel');
    expect(inf.apache?.candidates.length).toBeGreaterThan(0);
    for (const c of inf.apache!.candidates) expect(c.startsWith('rhel:'), c).toBe(true);
  });

  it('deb.sury.org: PHP は第三者リポジトリとして記録され、リリースを推定しない', async () => {
    const r = await request(handler(), PAGE.sury);
    expect(header(r, 'x-powered-by')).toContain('deb.sury.org');
    const inf = infer(r, realMap);
    expect(inf.php?.thirdParty?.kind).toBe('third-party');
    expect(inf.php?.confidence).toBe('none');
    expect(inf.php?.candidates).toEqual([]);
  });

  it('~bpo: PHP は Debian のバックポートとして記録され、リリースを推定しない', async () => {
    const r = await request(handler(), PAGE.bpo);
    expect(header(r, 'x-powered-by')).toMatch(/~bpo\d+/);
    const inf = infer(r, realMap);
    expect(inf.php?.thirdParty?.kind).toBe('backport');
    expect(inf.php?.confidence).toBe('none');
    expect(inf.php?.candidates).toEqual([]);
  });

  it('対応表に無い版: ディストリの印はあるが、版が対応表に無いので候補なし（none）', async () => {
    const r = await request(handler(), PAGE.unmapped);
    const all = [...bannerVersions(header(r, 'server')), ...bannerVersions(header(r, 'x-powered-by'))];
    expect(all.length).toBeGreaterThan(0);
    const inf = infer(r, realMap);
    const inferred = Object.entries(inf).filter(([, v]) => v !== undefined) as Array<[string, DistroInference]>;
    expect(inferred.length).toBeGreaterThan(0);
    for (const [product, v] of inferred) {
      expect(v.family, product).not.toBeNull();
      expect(v.thirdParty, product).toBeUndefined();
      expect(v.confidence, product).toBe('none');
      expect(v.candidates, product).toEqual([]);
      const ver = all.find((x) => x.product === product)!.version;
      expect(mapVersions(realMap, v.family!, product)).not.toContain(ver);
    }
  });
});

describe('T07: ディストリのバナーの版は対応表から取る（ページに直接書かない）', () => {
  const handler = (): Handler => mod.createRequestHandler({ distroMap: SYNTHETIC_MAP });

  it.each([PAGE.ubuntu, PAGE.debian, PAGE.rhel, PAGE.sury, PAGE.bpo])(
    '合成の対応表を渡すと、%s のバナーの版はすべて合成の対応表の版になる',
    async (p) => {
      const r = await request(handler(), p);
      const all = [...bannerVersions(header(r, 'server')), ...bannerVersions(header(r, 'x-powered-by'))];
      expect(all.length, p).toBeGreaterThan(0);
      for (const { product, version } of all) {
        expect(SYNTHETIC_VERSIONS, `${p}: ${product}/${version}`).toContain(version);
      }
    }
  );

  it('合成の対応表: Ubuntu のページは合成の ubuntu の Apache と PHP の版を使う', async () => {
    const r = await request(handler(), PAGE.ubuntu);
    expect(header(r, 'server')).toContain('Apache/9.4.71');
    expect(header(r, 'x-powered-by')).toContain('PHP/9.7.13-');
    const inf = infer(r, SYNTHETIC_MAP);
    expect(inf.apache?.candidates).toContain('ubuntu:90.04');
    expect(inf.php?.candidates).toContain('ubuntu:90.04');
  });

  it('合成の対応表: Debian のページはリリース番号と PHP の版を合成の debian から取る', async () => {
    const r = await request(handler(), PAGE.debian);
    expect(header(r, 'x-powered-by')).toContain('PHP/9.7.14-');
    expect(header(r, 'x-powered-by')).toMatch(/~deb91u\d+/);
    expect(infer(r, SYNTHETIC_MAP).php).toMatchObject({ family: 'debian', release: 'debian:91', confidence: 'high' });
  });

  it('合成の対応表: RHEL のページは合成の rhel の Apache の版を使う', async () => {
    const r = await request(handler(), PAGE.rhel);
    expect(header(r, 'server')).toContain('Apache/9.4.73');
    expect(infer(r, SYNTHETIC_MAP).apache?.candidates).toEqual(['rhel:92']);
  });

  it('合成の対応表: 第三者・バックポートの印は残る', async () => {
    const sury = await request(handler(), PAGE.sury);
    expect(infer(sury, SYNTHETIC_MAP).php?.thirdParty?.kind).toBe('third-party');
    const bpo = await request(handler(), PAGE.bpo);
    expect(infer(bpo, SYNTHETIC_MAP).php?.thirdParty?.kind).toBe('backport');
  });

  it('合成の対応表: 対応表に無い版のページは、合成の対応表のその系統・製品に無い版を使い、候補なしになる', async () => {
    const r = await request(handler(), PAGE.unmapped);
    const all = [...bannerVersions(header(r, 'server')), ...bannerVersions(header(r, 'x-powered-by'))];
    expect(all.length).toBeGreaterThan(0);
    const inferred = Object.entries(infer(r, SYNTHETIC_MAP)).filter(([, v]) => v !== undefined) as Array<
      [string, DistroInference]
    >;
    expect(inferred.length).toBeGreaterThan(0);
    for (const [product, v] of inferred) {
      expect(v.confidence, product).toBe('none');
      const ver = all.find((x) => x.product === product)!.version;
      expect(mapVersions(SYNTHETIC_MAP, v.family!, product)).not.toContain(ver);
    }
  });
});

// ---------------------------------------------------------------------------
// HTTPS 専用ヘッダーを HTTP で返すページ
// ---------------------------------------------------------------------------

describe('T07: HTTPS 専用ヘッダーの確認ページ', () => {
  it('COOP と COEP を返し、HTTP のページとして診断すると両方「対象外」になる', async () => {
    const r = await request(mod.createRequestHandler(), PAGE.httpsOnly);
    expect(header(r, 'cross-origin-opener-policy').length).toBeGreaterThan(0);
    expect(header(r, 'cross-origin-embedder-policy').length).toBeGreaterThan(0);
    const checks = checkHttpHeaders(r.headers, `${ORIGIN}${PAGE.httpsOnly}`, false);
    for (const prefix of ['SEC-COOP-', 'SEC-COEP-']) {
      const found = checks.filter((c) => c.checkId.startsWith(prefix));
      expect(found.map((c) => c.status), prefix).toEqual(['not-applicable']);
    }
  });
});
