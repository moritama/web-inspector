/**
 * T01: テストサーバーの「候補が 2 件以上になる」確認ページの受け入れテスト
 *
 * 設計メモ: 今回の版の作業フォルダ（docs/dev/ の下）の design/T01.md
 *
 * 指示書 §6 T01「テストサーバーに候補が 2 件以上になる確認ページが無ければ足す」。v1.8.1 の T07 のページには
 * 候補が 2 件以上になるページが無いので、/distro-multi-candidate を足す。
 * - 版は対応表（distro-map.json、または createRequestHandler に渡した対応表）から取る（ページに直接書かない）
 * - その版で推定すると、候補が 2 件以上（release なし・確信度 low・第三者でない）になる
 * - 対応表に 2 件以上のリリースにまたがる版が無ければ、候補が 2 件以上になる Server ヘッダーを返さない
 *
 * サーバーは起動しない（listen しない）。test-server/server.mjs が export するハンドラーに偽の req / res を渡す。
 */

import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { inferDistroFromHeaders } from '../src/detection/distro-inference';
import type { AdvisoryDistroSection, DistroInference } from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';

const SERVER_PATH = path.join(REPO_ROOT, 'test-server', 'server.mjs');
const DISTRO_MAP_PATH = path.join(REPO_ROOT, 'data', 'advisories', 'distro-map.json');
const PORT = 3000;
const ORIGIN = `http://localhost:${PORT}`;

/** 設計メモ「実装の方針」で決めたページのパス */
const MULTI_PATH = '/distro-multi-candidate';

interface MapEntry {
  family: string;
  release: string;
  codename: string | null;
  product: string;
  upstreamVersions: string[];
  sourcePackage: string;
  verifiedAt: string;
  evidenceUrl: string;
}
interface DistroMapLike {
  entries: MapEntry[];
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

function infer(r: FakeResponse, map: DistroMapLike): Array<[string, DistroInference]> {
  const section = { releases: [], map: map.entries } as unknown as AdvisoryDistroSection;
  const res = inferDistroFromHeaders({ server: r.headers['server'], 'x-powered-by': r.headers['x-powered-by'] }, section);
  return Object.entries(res).filter(([, v]) => v !== undefined) as Array<[string, DistroInference]>;
}

/** バナーに出ている「製品/版」の版だけを取り出す */
function bannerVersions(value: string): Array<{ product: string; version: string }> {
  const out: Array<{ product: string; version: string }> = [];
  const re = /(Apache|nginx|PHP|OpenSSL)\/(\d+(?:\.\d+)+[a-z]?)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(value)) !== null) out.push({ product: m[1].toLowerCase(), version: m[2] });
  return out;
}

function base(o: Partial<MapEntry>): MapEntry {
  return {
    family: 'ubuntu',
    release: 'ubuntu:90.04',
    codename: null,
    product: 'nginx',
    upstreamVersions: [],
    sourcePackage: 'nginx',
    verifiedAt: '',
    evidenceUrl: 'https://distro.example.test/',
    ...o,
  };
}

/** 2 つのリリースにまたがる版（9.18.5）を持つ合成の対応表（実在しない版・リリース） */
const SYNTHETIC_MULTI: DistroMapLike = {
  entries: [
    base({ release: 'ubuntu:90.04', product: 'apache', sourcePackage: 'apache2', upstreamVersions: ['9.4.71'] }),
    base({ release: 'ubuntu:90.04', product: 'nginx', upstreamVersions: ['9.18.5'] }),
    base({ release: 'ubuntu:91.04', product: 'nginx', upstreamVersions: ['9.18.5', '9.20.1'] }),
  ],
};

/** どの版も 1 つのリリースにしか無い合成の対応表 */
const SYNTHETIC_SINGLE: DistroMapLike = {
  entries: [
    base({ release: 'ubuntu:90.04', product: 'apache', sourcePackage: 'apache2', upstreamVersions: ['9.4.71'] }),
    base({ release: 'ubuntu:91.04', product: 'apache', sourcePackage: 'apache2', upstreamVersions: ['9.4.72'] }),
    base({ release: 'ubuntu:90.04', product: 'nginx', upstreamVersions: ['9.18.5'] }),
    base({ release: 'ubuntu:91.04', product: 'nginx', upstreamVersions: ['9.20.1'] }),
  ],
};

const realMap = JSON.parse(fs.readFileSync(DISTRO_MAP_PATH, 'utf-8')) as DistroMapLike;

let mod: ServerModule;
let listenSpy: { mockRestore: () => void };
let logSpy: { mockRestore: () => void };

beforeAll(async () => {
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

describe('T01: 候補が 2 件以上になる確認ページが起動時の一覧にある', () => {
  it(`${MULTI_PATH} が TEST_PAGES にあり、ラベルが付いている`, () => {
    const page = mod.TEST_PAGES.find((x) => x.path === MULTI_PATH);
    expect(page, `${MULTI_PATH} が一覧にありません`).toBeDefined();
    expect(page!.label.trim().length).toBeGreaterThan(0);
  });

  it(`${MULTI_PATH} の URL が起動時に表示する行にある`, () => {
    expect(mod.getStartupLines(PORT).some((l) => l.includes(`${ORIGIN}${MULTI_PATH}`))).toBe(true);
  });

  it('HTML を返し、本文に自分のパスを書いている（既定のページに落ちない）', async () => {
    const r = await request(mod.createRequestHandler(), MULTI_PATH);
    expect(r.statusCode).toBeLessThan(500);
    expect(header(r, 'content-type')).toMatch(/text\/html/i);
    expect(r.body).toContain(MULTI_PATH);
  });
});

describe('T01: 候補が 2 件以上になる確認ページ（同梱の対応表 distro-map.json）', () => {
  it('前提: 同梱の対応表に、同じ系統・製品で 2 件以上のリリースにまたがる版がある', () => {
    const seen = new Map<string, Set<string>>();
    for (const e of realMap.entries) {
      if (e.product !== 'apache' && e.product !== 'nginx') continue;
      for (const v of e.upstreamVersions) {
        const k = `${e.family}|${e.product}|${v}`;
        if (!seen.has(k)) seen.set(k, new Set());
        seen.get(k)!.add(e.release);
      }
    }
    expect(Array.from(seen.values()).some((s) => s.size >= 2)).toBe(true);
  });

  it('推定すると、候補が 2 件以上（release なし・確信度 low・第三者でない）の製品がある', async () => {
    const r = await request(mod.createRequestHandler(), MULTI_PATH);
    const multi = infer(r, realMap).filter(([, v]) => v.candidates.length >= 2);
    expect(multi.length, `Server: ${header(r, 'server')} / X-Powered-By: ${header(r, 'x-powered-by')}`).toBeGreaterThan(0);
    for (const [product, v] of multi) {
      expect(v.release, product).toBeNull();
      expect(v.confidence, product).toBe('low');
      expect(v.thirdParty, product).toBeUndefined();
      for (const c of v.candidates) expect(c.startsWith(`${v.family}:`), c).toBe(true);
    }
  });

  it('バナーの版は対応表にある版', async () => {
    const r = await request(mod.createRequestHandler(), MULTI_PATH);
    const all = [...bannerVersions(header(r, 'server')), ...bannerVersions(header(r, 'x-powered-by'))];
    expect(all.length).toBeGreaterThan(0);
    const versions = new Set(realMap.entries.flatMap((e) => e.upstreamVersions));
    for (const { product, version } of all) expect(versions.has(version), `${product}/${version}`).toBe(true);
  });
});

describe('T01: 候補が 2 件以上になる確認ページの版は対応表から取る（ページに直接書かない）', () => {
  it('合成の対応表を渡すと、2 つのリリースにまたがる合成の版を使い、候補はその 2 つ', async () => {
    const r = await request(mod.createRequestHandler({ distroMap: SYNTHETIC_MULTI }), MULTI_PATH);
    expect(header(r, 'server')).toContain('9.18.5');
    const multi = infer(r, SYNTHETIC_MULTI).filter(([, v]) => v.candidates.length >= 2);
    expect(multi.length).toBeGreaterThan(0);
    expect([...multi[0][1].candidates].sort()).toEqual(['ubuntu:90.04', 'ubuntu:91.04']);
  });

  it('陰性: どの版も 1 つのリリースにしか無い対応表では、候補が 2 件以上になるヘッダーを返さない（ページは返す）', async () => {
    const r = await request(mod.createRequestHandler({ distroMap: SYNTHETIC_SINGLE }), MULTI_PATH);
    expect(r.statusCode).toBeLessThan(500);
    expect(r.body).toContain(MULTI_PATH);
    expect(infer(r, SYNTHETIC_SINGLE).filter(([, v]) => v.candidates.length >= 2)).toEqual([]);
  });

  it('陰性: 既存のディストリのページ（Ubuntu・RHEL）は変わらず、候補が 2 件以上のページと別のヘッダーを返す', async () => {
    const h = mod.createRequestHandler();
    const multi = await request(h, MULTI_PATH);
    for (const p of ['/distro-ubuntu-apache-php', '/distro-rhel', '/distro-unmapped']) {
      const r = await request(h, p);
      expect(r.body, p).toContain(p);
      expect(header(r, 'server'), p).not.toBe(header(multi, 'server'));
    }
  });
});
