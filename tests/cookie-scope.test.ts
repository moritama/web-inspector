/**
 * Cookie のスコープと確信度（v1.8.2 T03 / A、指示書 §4.1・H1〜H3）
 *
 * - 根拠がすべて Cookie 名（cookie-name）で、どの Cookie も host-only でない（親ドメイン・apex の Domain、スコープ不明）
 *   → 確信度 35（low）、runtimeStatus は possible、detectionMethod は 'direct' のまま
 * - 他の根拠が 1 つでもあれば下げない。同じ名前に host-only が 1 つでもあれば host
 * - 下げた技術から連動する技術は high にならない。Classic ASP / ASP.NET の排他判定は従来どおり（名前だけで見る）
 *
 * 再現データは *.example.test の合成データ。確信度の値は H2 の 35 以外を直書きせず、ルールの weight から求める。
 */
import { describe, expect, it } from 'vitest';
import { DetectionEngine, type DetectionInput } from '../src/detection/engine';
import { ALL_TECHNOLOGY_RULES } from '../src/detection/rules';
import type {
  DetectedTechnology,
  DomSignals,
  Evidence,
  InspectedCookieInfo,
} from '../src/shared/types';

const PAGE_URL = 'https://www.example.test/';
const APEX_URL = 'https://example.test/';
const GA_SCRIPT = 'https://www.googletagmanager.com/gtag/js?id=G-TEST000001';

/** H2 の確信度（根拠が親ドメインの Cookie 名だけのとき） */
const DOWNGRADED_CONFIDENCE = 35;

const emptyDom = (url: string, overrides: Partial<DomSignals> = {}): DomSignals => ({
  url,
  title: 'Cookie scope fixture',
  metaTags: [],
  scriptUrls: [],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
  ...overrides,
});

/** chrome.cookies が返す形の Cookie（値は検出に使わない） */
const hostCookie = (name: string, host = 'www.example.test'): InspectedCookieInfo => ({
  name,
  domain: host,
  path: '/',
  secure: true,
  httpOnly: false,
  sameSite: 'lax',
  session: false,
  hostOnly: true,
});

const domainCookie = (name: string, domain = '.example.test'): InspectedCookieInfo => ({
  name,
  domain,
  path: '/',
  secure: true,
  httpOnly: false,
  sameSite: 'lax',
  session: false,
  hostOnly: false,
});

interface InputOptions {
  url?: string;
  cookies?: InspectedCookieInfo[];
  documentCookies?: string[];
  setCookie?: string[];
  headers?: Record<string, string[]>;
  scriptUrls?: string[];
}

const buildInput = (opts: InputOptions): DetectionInput => {
  const url = opts.url ?? PAGE_URL;
  const responseHeaders: Record<string, string[]> = { ...(opts.headers ?? {}) };
  if (opts.setCookie) {
    responseHeaders['set-cookie'] = opts.setCookie;
  }
  return {
    url,
    dom: emptyDom(url, {
      cookiesFromDocument: opts.documentCookies ?? [],
      scriptUrls: opts.scriptUrls ?? [],
    }),
    network: {
      url,
      responseHeaders,
      cookies: opts.cookies ?? [],
    },
  };
};

const detect = (opts: InputOptions): DetectedTechnology[] =>
  new DetectionEngine().detect(buildInput(opts));

const find = (results: DetectedTechnology[], technology: string): DetectedTechnology | undefined =>
  results.find((r) => r.technology === technology);

/** Cookie のスコープ（実装の方針: Evidence.cookieScope） */
const scopeOf = (ev: Evidence): string | undefined =>
  (ev as Evidence & { cookieScope?: string }).cookieScope;

/** 確信度を下げた印（実装の方針: DetectedTechnology.cookieScopeDowngraded） */
const downgradedFlag = (tech: DetectedTechnology | undefined): boolean =>
  Boolean((tech as (DetectedTechnology & { cookieScopeDowngraded?: boolean }) | undefined)?.cookieScopeDowngraded);

/** ルール JSON の Cookie の signal の weight（従来の確信度の基準。値を直書きしない） */
const cookieWeight = (ruleId: string, target: string): number => {
  const rule = ALL_TECHNOLOGY_RULES.find((r) => r.id === ruleId);
  const signal = rule?.signals.find((s) => s.type === 'cookie' && s.target === target);
  if (!signal || typeof signal.weight !== 'number') {
    throw new Error(`rule ${ruleId} に Cookie ${target} の signal がありません`);
  }
  return signal.weight;
};

/** 下げられた技術の共通の期待（H2） */
const expectDowngraded = (tech: DetectedTechnology | undefined): void => {
  expect(tech).toBeDefined();
  expect(tech?.confidence).toBe(DOWNGRADED_CONFIDENCE);
  expect(tech?.confidenceLevel).toBe('low');
  expect(tech?.runtimeStatus).toBe('possible');
  expect(tech?.detectionMethod).toBe('direct');
  expect(downgradedFlag(tech)).toBe(true);
};

/** 下げられていない（従来どおり）ことの共通の期待 */
const expectNotDowngraded = (tech: DetectedTechnology | undefined): void => {
  expect(tech).toBeDefined();
  expect(tech?.confidence).toBeGreaterThan(DOWNGRADED_CONFIDENCE);
  expect(downgradedFlag(tech)).toBe(false);
};

describe('v1.8.2 T03 (A): Cookie のスコープと確信度', () => {
  describe('前提: 受け入れテストが使うルールの weight（従来なら一覧に出る値）', () => {
    it('_ga・PHPSESSID・laravel_session・ASPSESSIONID の weight は 50 以上、csrftoken は 50 未満', () => {
      expect(cookieWeight('google-analytics', '_ga')).toBeGreaterThanOrEqual(80);
      expect(cookieWeight('php', 'PHPSESSID')).toBeGreaterThanOrEqual(50);
      expect(cookieWeight('php', 'PHPSESSID')).toBeLessThan(80);
      expect(cookieWeight('laravel', 'laravel_session')).toBeGreaterThanOrEqual(80);
      expect(cookieWeight('classic-asp', 'ASPSESSIONID')).toBeGreaterThanOrEqual(80);
      expect(cookieWeight('python-django', 'csrftoken')).toBeLessThan(50);
    });
  });

  describe('chrome.cookies の経路（hostOnly）', () => {
    it('陽性: 親ドメイン（.example.test、hostOnly: false）の _ga だけ → Google Analytics は low・possible（確信度 35、direct のまま）', () => {
      const ga = find(detect({ cookies: [domainCookie('_ga')] }), 'Google Analytics');
      expectDowngraded(ga);
      expect(ga?.evidence.every((e) => e.type === 'cookie-name')).toBe(true);
    });

    it('陽性（H1）: apex のホスト（example.test）で .example.test の _ga（hostOnly: false）も host-only でない側 → low', () => {
      const ga = find(
        detect({ url: APEX_URL, cookies: [domainCookie('_ga', '.example.test')] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
    });

    it('陰性: 親ドメインの _ga ＋ GA の script-url → high のまま（confirmed）', () => {
      const ga = find(
        detect({ cookies: [domainCookie('_ga')], scriptUrls: [GA_SCRIPT] }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
      expect(ga?.confidenceLevel).toBe('high');
      expect(ga?.runtimeStatus).toBe('confirmed');
    });

    it('陰性: host-only の _ga だけ → 従来どおり high（weight のとおり）', () => {
      const ga = find(detect({ cookies: [hostCookie('_ga')] }), 'Google Analytics');
      expectNotDowngraded(ga);
      expect(ga?.confidence).toBe(cookieWeight('google-analytics', '_ga'));
      expect(ga?.confidenceLevel).toBe('high');
    });

    it('陰性: host-only の PHPSESSID → 従来どおり PHP は medium（weight のとおり）', () => {
      const php = find(detect({ cookies: [hostCookie('PHPSESSID')] }), 'PHP');
      expectNotDowngraded(php);
      expect(php?.confidence).toBe(cookieWeight('php', 'PHPSESSID'));
      expect(php?.confidenceLevel).toBe('medium');
    });

    it('陽性: 親ドメインの PHPSESSID だけ → PHP は low・possible', () => {
      expectDowngraded(find(detect({ cookies: [domainCookie('PHPSESSID')] }), 'PHP'));
    });

    it('陰性: 親ドメインの PHPSESSID ＋ X-Powered-By: PHP（ヘッダーの根拠）→ 下げない', () => {
      const php = find(
        detect({ cookies: [domainCookie('PHPSESSID')], headers: { 'x-powered-by': ['PHP/8.2.10'] } }),
        'PHP'
      );
      expectNotDowngraded(php);
    });

    it('互換: hostOnly の無い Cookie（合成データ・古い形）は従来どおり下げない', () => {
      const ga = find(detect({ cookies: [{ name: '_ga', domain: 'www.example.test' }] }), 'Google Analytics');
      expectNotDowngraded(ga);
      expect(ga?.confidenceLevel).toBe('high');
    });
  });

  describe('Set-Cookie レスポンスヘッダーの経路（Domain 属性）', () => {
    it('陽性: Domain 属性あり（親ドメイン）の _ga だけ → low・possible', () => {
      const ga = find(
        detect({ setCookie: ['_ga=GA1.2.1111111111.1700000000; Domain=.example.test; Path=/; Max-Age=63072000'] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
    });

    it('陽性: Domain の値がホストと同じでも Domain 属性ありは host-only でない（RFC 6265 §5.3 6） → low', () => {
      const ga = find(
        detect({ setCookie: ['_ga=GA1.2.1111111111.1700000000; Path=/; Domain=www.example.test'] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
    });

    it('陽性: 属性名は大文字小文字を区別しない（domain=）→ low', () => {
      const ga = find(
        detect({ setCookie: ['_ga=GA1.2.1111111111.1700000000; path=/; domain=example.test'] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
    });

    it('陰性: Domain 属性なしの _ga → host として従来どおり high', () => {
      const ga = find(
        detect({ setCookie: ['_ga=GA1.2.1111111111.1700000000; Path=/; Max-Age=63072000; Secure'] }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
      expect(ga?.confidenceLevel).toBe('high');
    });

    it('陰性: ヘッダー名の大文字（Set-Cookie）でも Domain なしは host', () => {
      const ga = find(
        detect({ headers: { 'Set-Cookie': ['_ga=GA1.2.1111111111.1700000000; Path=/'] } }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
    });
  });

  describe('document.cookie の経路（スコープ不明、H3）', () => {
    it('陽性: document.cookie だけにある _ga → 下げる（unknown は host-only でない側）', () => {
      const results = detect({ documentCookies: ['_ga'] });
      const ga = find(results, 'Google Analytics');
      expectDowngraded(ga);
      const ev = ga?.evidence.find((e) => e.type === 'cookie-name' && e.name === '_ga');
      expect(ev && scopeOf(ev)).toBe('unknown');
    });

    it('陰性: document.cookie にも chrome.cookies（host-only）にもある _ga → 下げない（host が優先）', () => {
      const ga = find(
        detect({ documentCookies: ['_ga'], cookies: [hostCookie('_ga')] }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
      const ev = ga?.evidence.find((e) => e.type === 'cookie-name' && e.name === '_ga');
      expect(ev && scopeOf(ev)).toBe('host');
    });

    it('陰性: document.cookie にも Set-Cookie（Domain なし）にもある _ga → 下げない', () => {
      const ga = find(
        detect({ documentCookies: ['_ga'], setCookie: ['_ga=GA1.2.1111111111.1700000000; Path=/'] }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
    });

    it('陽性: document.cookie と親ドメインの chrome.cookies の _ga → 下げる（根拠のスコープは domain）', () => {
      const ga = find(
        detect({ documentCookies: ['_ga'], cookies: [domainCookie('_ga')] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
      const ev = ga?.evidence.find((e) => e.type === 'cookie-name' && e.name === '_ga');
      expect(ev && scopeOf(ev)).toBe('domain');
    });
  });

  describe('同じ名前が複数（host と domain が混在）', () => {
    it('陰性: chrome.cookies に同じ名前 _ga が host-only と親ドメインの 2 件 → 下げない（順番に依らない）', () => {
      for (const cookies of [
        [domainCookie('_ga'), hostCookie('_ga')],
        [hostCookie('_ga'), domainCookie('_ga')],
      ]) {
        const ga = find(detect({ cookies }), 'Google Analytics');
        expectNotDowngraded(ga);
        expect(ga?.confidenceLevel).toBe('high');
        const cookieEvidences = ga?.evidence.filter((e) => e.type === 'cookie-name') ?? [];
        // 同じ名前の根拠は 1 件（IMPL-12 の重複除去は従来どおり）で、スコープは host
        expect(cookieEvidences).toHaveLength(1);
        expect(scopeOf(cookieEvidences[0])).toBe('host');
      }
    });

    it('陰性: 経路をまたいだ混在（chrome.cookies は親ドメイン、Set-Cookie は Domain なし）→ 下げない', () => {
      const ga = find(
        detect({ cookies: [domainCookie('_ga')], setCookie: ['_ga=GA1.2.1111111111.1700000000; Path=/'] }),
        'Google Analytics'
      );
      expectNotDowngraded(ga);
    });

    it('陽性: 同じ名前が親ドメインで 2 件（.example.test と .www.example.test）→ 下げる', () => {
      const ga = find(
        detect({ cookies: [domainCookie('_ga', '.example.test'), domainCookie('_ga', '.www.example.test')] }),
        'Google Analytics'
      );
      expectDowngraded(ga);
    });

    it('陽性: 1 つの技術に別々の Cookie 名が 2 つ（ai_session・ai_user）あり、どちらも親ドメイン → 下げる', () => {
      const ai = find(
        detect({ cookies: [domainCookie('ai_session'), domainCookie('ai_user')] }),
        'Application Insights'
      );
      expectDowngraded(ai);
    });

    it('陰性: 別々の Cookie 名が 2 つのうち 1 つが host-only（ai_session は host、ai_user は親ドメイン）→ 下げない', () => {
      const ai = find(
        detect({ cookies: [hostCookie('ai_session'), domainCookie('ai_user')] }),
        'Application Insights'
      );
      expectNotDowngraded(ai);
    });
  });

  describe('根拠のスコープ（Evidence.cookieScope）', () => {
    it('chrome.cookies の host-only は host、hostOnly: false は domain、Set-Cookie の Domain あり／なしは domain／host', () => {
      const hostEv = find(detect({ cookies: [hostCookie('_ga')] }), 'Google Analytics')?.evidence.find(
        (e) => e.type === 'cookie-name'
      );
      const domainEv = find(detect({ cookies: [domainCookie('_ga')] }), 'Google Analytics')?.evidence.find(
        (e) => e.type === 'cookie-name'
      );
      const setDomainEv = find(
        detect({ setCookie: ['_ga=1; Domain=example.test'] }),
        'Google Analytics'
      )?.evidence.find((e) => e.type === 'cookie-name');
      const setHostEv = find(detect({ setCookie: ['_ga=1; Path=/'] }), 'Google Analytics')?.evidence.find(
        (e) => e.type === 'cookie-name'
      );
      expect(hostEv && scopeOf(hostEv)).toBe('host');
      expect(domainEv && scopeOf(domainEv)).toBe('domain');
      expect(setDomainEv && scopeOf(setDomainEv)).toBe('domain');
      expect(setHostEv && scopeOf(setHostEv)).toBe('host');
    });
  });

  describe('一覧に出すかどうか（警告を増やしすぎない）', () => {
    it('陰性: 従来も確信度 50 未満で一覧に出なかった Cookie（親ドメインの csrftoken だけ）は、下げても一覧に出さない', () => {
      const results = detect({ cookies: [domainCookie('csrftoken')] });
      expect(find(results, 'Django')).toBeUndefined();
    });

    it('陰性: host-only の csrftoken だけも従来どおり一覧に出ない', () => {
      expect(find(detect({ cookies: [hostCookie('csrftoken')] }), 'Django')).toBeUndefined();
    });

    it('陰性: 汎用の *_session と XSRF-TOKEN がどちらも親ドメインなら、Laravel を medium（70）に引き上げない', () => {
      const laravel = find(
        detect({ cookies: [domainCookie('myapp_session'), domainCookie('XSRF-TOKEN')] }),
        'Laravel'
      );
      if (laravel) {
        expect(laravel.confidence).toBeLessThanOrEqual(DOWNGRADED_CONFIDENCE);
        expect(laravel.confidenceLevel).toBe('low');
      }
    });

    it('陰性（対照）: 汎用の *_session と XSRF-TOKEN がどちらも host-only なら従来どおり Laravel は medium', () => {
      const laravel = find(
        detect({ cookies: [hostCookie('myapp_session'), hostCookie('XSRF-TOKEN')] }),
        'Laravel'
      );
      expect(laravel).toBeDefined();
      expect(laravel?.confidenceLevel).toBe('medium');
    });
  });

  describe('連動検知（下げた技術から high が連動しない）', () => {
    it('陽性: 親ドメインの laravel_session だけ → Laravel は low、PHP は high にならない', () => {
      const results = detect({ cookies: [domainCookie('laravel_session')] });
      expectDowngraded(find(results, 'Laravel'));
      const php = find(results, 'PHP');
      expect(php?.confidenceLevel).not.toBe('high');
      expect(php?.inferredFrom).not.toBe('Laravel');
    });

    it('陰性（対照）: host-only の laravel_session → Laravel は high で、PHP が連動する（従来どおり）', () => {
      const results = detect({ cookies: [hostCookie('laravel_session')] });
      const laravel = find(results, 'Laravel');
      expectNotDowngraded(laravel);
      expect(laravel?.confidenceLevel).toBe('high');
      const php = find(results, 'PHP');
      expect(php).toBeDefined();
      expect(php?.evidence.some((e) => e.source === 'Laravel')).toBe(true);
    });

    it('陽性: document.cookie だけの laravel_session でも PHP は high にならない', () => {
      const results = detect({ documentCookies: ['laravel_session'] });
      expectDowngraded(find(results, 'Laravel'));
      expect(find(results, 'PHP')?.confidenceLevel).not.toBe('high');
    });
  });

  describe('Classic ASP / ASP.NET の排他判定（従来どおり、名前だけで見る）', () => {
    it('host-only の ASPSESSIONID* だけ → Classic ASP（従来どおりの確信度）、ASP.NET は出ない', () => {
      const results = detect({ cookies: [hostCookie('ASPSESSIONIDQATRSDCB')] });
      const asp = find(results, 'Classic ASP');
      expectNotDowngraded(asp);
      expect(asp?.confidence).toBe(cookieWeight('classic-asp', 'ASPSESSIONID'));
      expect(find(results, 'ASP.NET')).toBeUndefined();
    });

    it('親ドメインの ASPSESSIONID* だけ → Classic ASP は low に下がり、ASP.NET は従来どおり出ない', () => {
      const results = detect({ cookies: [domainCookie('ASPSESSIONIDQATRSDCB')] });
      expectDowngraded(find(results, 'Classic ASP'));
      expect(find(results, 'ASP.NET')).toBeUndefined();
    });

    it('親ドメインの ASPSESSIONID* ＋ host-only の ASP.NET_SessionId → Classic ASP は出ず、ASP.NET は従来どおり', () => {
      const results = detect({
        cookies: [domainCookie('ASPSESSIONIDQATRSDCB'), hostCookie('ASP.NET_SessionId')],
      });
      expect(find(results, 'Classic ASP')).toBeUndefined();
      const aspnet = find(results, 'ASP.NET');
      expectNotDowngraded(aspnet);
      expect(aspnet?.confidence).toBe(cookieWeight('aspnet', 'ASP.NET_SessionId'));
    });

    it('host-only の ASPSESSIONID* ＋ 親ドメインの ASP.NET_SessionId → Classic ASP は出ない（スコープに依らず排他）、ASP.NET は low', () => {
      const results = detect({
        cookies: [hostCookie('ASPSESSIONIDQATRSDCB'), domainCookie('ASP.NET_SessionId')],
      });
      expect(find(results, 'Classic ASP')).toBeUndefined();
      expectDowngraded(find(results, 'ASP.NET'));
    });

    it('document.cookie だけの ASPSESSIONID* でも排他判定は効く（ASP.NET は出ない）', () => {
      const results = detect({ documentCookies: ['ASPSESSIONIDQATRSDCB'] });
      expect(find(results, 'ASP.NET')).toBeUndefined();
      expectDowngraded(find(results, 'Classic ASP'));
    });
  });
});
