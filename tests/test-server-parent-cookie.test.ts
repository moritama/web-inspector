/**
 * サブドメインをまたぐ確認ページ（v1.8.2 T04 / A、指示書 §6 T04）
 *
 * 目視確認の手順: 親ドメインで _ga を発行するページ（issuer）を開いた後、別のサブドメインのページ（target）を調査する
 * → GA が low、§14 に注記。
 *
 * - /parent-cookie-issuer: Host が *.localtest.me なら Domain=localtest.me、*.example.test なら Domain=example.test の _ga を発行する。
 *   それ以外の Host（localhost など）では Domain 付きの _ga を発行しない（ブラウザが拒否するため）
 * - /parent-cookie-target: _ga を発行せず、GA のスクリプトも読み込まない（GA の根拠が親ドメインの Cookie だけになる）
 * - 名前解決できない環境の代わりの手順（/etc/hosts に *.example.test を足す）をページに書く
 *
 * サーバーは起動しない（listen しない）。test-server/server.mjs が export するハンドラーに偽の req / res を渡す。
 */
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { DetectionEngine } from '../src/detection/engine';
import type { DomSignals } from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';

const SERVER_PATH = path.join(REPO_ROOT, 'test-server', 'server.mjs');
const PORT = 3000;

/** 設計メモ「実装の方針」で決めたパスとホスト */
const ISSUER_PATH = '/parent-cookie-issuer';
const TARGET_PATH = '/parent-cookie-target';
const ISSUER_HOST = 'issuer.localtest.me';
const TARGET_HOST = 'app.localtest.me';
const PARENT = 'localtest.me';
const HOSTS_ISSUER = 'issuer.example.test';
const HOSTS_TARGET = 'app.example.test';
const HOSTS_PARENT = 'example.test';

type Handler = (req: unknown, res: unknown) => unknown;

interface ServerModule {
  createRequestHandler: (options?: unknown) => Handler;
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

/** ハンドラーに偽の GET リクエスト（Host つき）を渡し、res.end が呼ばれるまで待つ */
function request(handler: Handler, pathname: string, host: string): Promise<FakeResponse> {
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
    const req = { url: pathname, method: 'GET', headers: { host: `${host}:${PORT}` } };
    try {
      handler(req, res);
    } catch (e) {
      clearTimeout(timer);
      reject(e);
    }
  });
}

const setCookies = (r: FakeResponse): string[] => r.headers['set-cookie'] || [];

/** Set-Cookie の属性（最初の ; より後）の Domain の値。無ければ null */
const domainAttr = (raw: string): string | null => {
  const semi = raw.indexOf(';');
  if (semi < 0) return null;
  for (const attr of raw.slice(semi + 1).split(';')) {
    const eq = attr.indexOf('=');
    if (eq < 0) continue;
    if (attr.slice(0, eq).trim().toLowerCase() === 'domain') {
      const v = attr.slice(eq + 1).trim().replace(/^\./, '');
      return v || null;
    }
  }
  return null;
};

const cookieName = (raw: string): string => raw.slice(0, raw.indexOf('=')).trim();
const gaCookies = (r: FakeResponse): string[] => setCookies(r).filter((c) => cookieName(c) === '_ga');

const GA_SCRIPT_RE = /googletagmanager\.com\/gtag\/js|google-analytics\.com\/(?:analytics|ga)\.js/i;

let mod: ServerModule;

beforeAll(async () => {
  mod = (await import(pathToFileURL(SERVER_PATH).href)) as ServerModule;
});

describe('T04: 確認ページの一覧と起動時の表示', () => {
  it.each([[ISSUER_PATH], [TARGET_PATH]])('%s が TEST_PAGES にあり、ラベルが付いている', (p) => {
    const page = mod.TEST_PAGES.find((x) => x.path === p);
    expect(page, `${p} が一覧にありません`).toBeDefined();
    expect(page!.label.trim().length).toBeGreaterThan(0);
  });

  it('起動時の行に、localtest.me のサブドメインの URL（issuer と target）がある', () => {
    const lines = mod.getStartupLines(PORT);
    expect(lines.some((l) => l.includes(`http://${ISSUER_HOST}:${PORT}${ISSUER_PATH}`))).toBe(true);
    expect(lines.some((l) => l.includes(`http://${TARGET_HOST}:${PORT}${TARGET_PATH}`))).toBe(true);
  });

  it('起動時の行はポート番号を引数どおりに使う', () => {
    const lines = mod.getStartupLines(4321);
    expect(lines.some((l) => l.includes(`http://${ISSUER_HOST}:4321${ISSUER_PATH}`))).toBe(true);
  });
});

describe('T04: /parent-cookie-issuer（親ドメインで _ga を発行する）', () => {
  it('陽性: Host が issuer.localtest.me → Domain=localtest.me の _ga を発行し、HTML を返す', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, ISSUER_HOST);
    expect(r.statusCode).toBeLessThan(400);
    expect((r.headers['content-type'] || []).join(',')).toMatch(/text\/html/i);
    expect(r.body).toContain(ISSUER_PATH);
    const ga = gaCookies(r);
    expect(ga.length).toBeGreaterThan(0);
    expect(ga.some((c) => domainAttr(c)?.toLowerCase() === PARENT)).toBe(true);
  });

  it('陽性: Host が issuer.example.test（/etc/hosts の代わりの手順）→ Domain=example.test の _ga', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, HOSTS_ISSUER);
    expect(gaCookies(r).some((c) => domainAttr(c)?.toLowerCase() === HOSTS_PARENT)).toBe(true);
  });

  it('陰性: Host が localhost → Domain 付きの _ga を発行しない（案内のページを返す）', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, 'localhost');
    expect(r.statusCode).toBeLessThan(400);
    expect(r.body).toContain(ISSUER_PATH);
    expect(gaCookies(r).some((c) => domainAttr(c) !== null)).toBe(false);
    expect(r.body).toContain(`${ISSUER_HOST}:${PORT}${ISSUER_PATH}`);
  });

  it('GA のスクリプトを読み込まない（GA の根拠を Cookie だけにする）', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, ISSUER_HOST);
    expect(r.body).not.toMatch(GA_SCRIPT_RE);
  });

  it('名前解決できない環境の代わりの手順（/etc/hosts と *.example.test のホスト名）を書いている', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, ISSUER_HOST);
    expect(r.body).toContain('/etc/hosts');
    expect(r.body).toContain(HOSTS_ISSUER);
    expect(r.body).toContain(HOSTS_TARGET);
    expect(r.body).toContain('127.0.0.1');
  });

  it('target のページ（別のサブドメイン）への案内がある', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, ISSUER_HOST);
    expect(r.body).toContain(`${TARGET_HOST}:${PORT}${TARGET_PATH}`);
  });

  it('発行した Set-Cookie を検出エンジンに渡すと、GA は low（T03 の判定と合う）', async () => {
    const r = await request(mod.createRequestHandler(), ISSUER_PATH, ISSUER_HOST);
    const url = `http://${TARGET_HOST}:${PORT}${TARGET_PATH}`;
    const dom: DomSignals = {
      url,
      title: 'target',
      metaTags: [],
      scriptUrls: [],
      linkUrls: [],
      domMarkers: [],
      htmlSnippets: [],
      mixedContent: [],
      cookiesFromDocument: [],
      cssAssets: [],
    };
    const techs = new DetectionEngine().detect({
      url,
      dom,
      network: { url, responseHeaders: { 'set-cookie': gaCookies(r) }, cookies: [] },
    });
    const ga = techs.find((t) => t.technology === 'Google Analytics');
    expect(ga).toBeDefined();
    expect(ga!.confidenceLevel).toBe('low');
  });
});

describe('T04: /parent-cookie-target（別のサブドメインで調べるページ）', () => {
  it('HTML を返し、本文に自分のパスを書いている（既定のページに落ちない）', async () => {
    const r = await request(mod.createRequestHandler(), TARGET_PATH, TARGET_HOST);
    expect(r.statusCode).toBeLessThan(400);
    expect((r.headers['content-type'] || []).join(',')).toMatch(/text\/html/i);
    expect(r.body).toContain(TARGET_PATH);
  });

  it('陰性: _ga を発行せず、GA のスクリプトも読み込まない', async () => {
    const r = await request(mod.createRequestHandler(), TARGET_PATH, TARGET_HOST);
    expect(gaCookies(r)).toEqual([]);
    expect(r.body).not.toMatch(GA_SCRIPT_RE);
  });

  it('issuer のページへの案内がある', async () => {
    const r = await request(mod.createRequestHandler(), TARGET_PATH, TARGET_HOST);
    expect(r.body).toContain(`${ISSUER_HOST}:${PORT}${ISSUER_PATH}`);
  });
});

describe('T04: /clear-cookies が親ドメインの _ga も消す', () => {
  it('Host が *.localtest.me → Domain=localtest.me の _ga を期限切れにする', async () => {
    const r = await request(mod.createRequestHandler(), '/clear-cookies', TARGET_HOST);
    const expired = gaCookies(r).filter((c) => /max-age=0/i.test(c));
    expect(expired.some((c) => domainAttr(c)?.toLowerCase() === PARENT)).toBe(true);
  });

  it('既存の host-only の _ga の消去は残る', async () => {
    const r = await request(mod.createRequestHandler(), '/clear-cookies', 'localhost');
    expect(gaCookies(r).some((c) => /max-age=0/i.test(c) && domainAttr(c) === null)).toBe(true);
  });
});
