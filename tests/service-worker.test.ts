import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { DomSignals, FindingException, InspectedCookieInfo } from '../src/shared/types';

const createMockDomSignals = (overrides: Partial<DomSignals> = {}): DomSignals => ({
  url: 'https://example.com/',
  title: 'Example Domain',
  metaTags: [{ name: 'generator', content: 'WordPress 6.4.2' }],
  scriptUrls: ['https://unpkg.com/react@18.2.0/umd/react.production.min.js'],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
  ...overrides,
});

const createMockDeps = (overrides: Partial<InspectionDependencies> = {}): InspectionDependencies => ({
  tab: { id: 101, url: 'https://example.com/' },
  fetchDomSignals: vi.fn().mockResolvedValue(createMockDomSignals()),
  fetchRuntimeVersions: vi.fn().mockResolvedValue({
    versions: { react: '18.2.0' },
    frameworkMarkers: ['__reactContainer$'],
  }),
  getCachedHeaders: vi.fn().mockResolvedValue({
    url: 'https://example.com/',
    headers: {
      server: ['Apache/2.4.58 (Ubuntu)'],
      'x-powered-by': ['PHP/8.2.10'],
    },
  }),
  getInspectedCookies: vi.fn().mockResolvedValue([
    {
      name: 'laravel_session',
      domain: 'example.com',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      session: true,
      issues: [],
    } as InspectedCookieInfo,
  ]),
  getAllFindingExceptions: vi.fn().mockResolvedValue([] as FindingException[]),
  saveReport: vi.fn().mockResolvedValue(undefined),
  updateBadge: vi.fn(),
  hasWebRequestPermission: true,
  ...overrides,
});

describe('Service Worker 調査統合テスト (executeInspection)', () => {
  it('DOM、MAINワールドランタイム、HTTPヘッダー、Cookieを総合して例外なく完全なレポートを生成すること', async () => {
    const deps = createMockDeps();
    const report = await executeInspection(deps);

    // 基本構造の検証
    expect(report).toBeDefined();
    expect(report.url).toBe('https://example.com/');
    expect(report.hostname).toBe('example.com');
    expect(report.technologies.length).toBeGreaterThan(0);

    // React (MAINワールド実行時情報由来) の検出確認
    const reactTech = report.technologies.find((t) => t.technology === 'React');
    expect(reactTech).toBeDefined();
    expect(reactTech?.version).toBe('18.2.0');
    expect(reactTech?.detectionMethod).toBe('direct');
    expect(reactTech?.runtimeStatus).toBe('confirmed');

    // Apache (Serverヘッダー由来) の肯定検出確認
    const apacheTech = report.technologies.find((t) => t.technology === 'Apache');
    expect(apacheTech).toBeDefined();
    expect(apacheTech?.version).toBe('2.4.58');

    // PHP (X-Powered-Byヘッダー由来) の肯定検出確認
    const phpTech = report.technologies.find((t) => t.technology === 'PHP');
    expect(phpTech).toBeDefined();

    // 履歴保存とバッジ更新の呼び出し確認
    expect(deps.saveReport).toHaveBeenCalledWith(report);
    expect(deps.updateBadge).toHaveBeenCalled();
  });

  it('chrome:// などのブラウザ管理ページでは速やかに例外をスローすること', async () => {
    const deps = createMockDeps({
      tab: { id: 999, url: 'chrome://extensions' },
    });

    await expect(executeInspection(deps)).rejects.toThrow('ブラウザの内部管理ページは調査対象外です');
    expect(deps.fetchDomSignals).not.toHaveBeenCalled();
  });

  it('未定義変数の参照エラー (ReferenceError: runtimeVersions is not defined) が発生せず、安全に完了すること', async () => {
    // 過去にクラッシュしたランタイム情報渡しの回帰テスト
    const deps = createMockDeps({
      fetchRuntimeVersions: vi.fn().mockResolvedValue({
        versions: { jquery: '3.6.0', bootstrap5: '5.3.2' },
        frameworkMarkers: [],
      }),
    });

    const report = await executeInspection(deps);
    expect(report).toBeDefined();
    expect(report.summary.totalTechnologies).toBeGreaterThanOrEqual(1);
  });

  it('AngularJS 1.7.9のように修正版ありと修正版なしが混在する場合でも、移行推奨の文言が生成されること', async () => {
    // 1.7.9 では CVE-2020-7676 (fix: 1.8.0) と CVE-2022-25869 (fix: null) が併発する
    const deps = createMockDeps({
      fetchDomSignals: vi.fn().mockResolvedValue(createMockDomSignals({
        scriptUrls: ['https://ajax.googleapis.com/ajax/libs/angularjs/1.7.9/angular.min.js'],
        domMarkers: ['ng-app'],
      })),
      fetchRuntimeVersions: vi.fn().mockResolvedValue({
        versions: { angularjs: '1.7.9' },
        frameworkMarkers: [],
      }),
    });

    const report = await executeInspection(deps);
    const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-ANGULARJS');
    expect(cveCheck).toBeDefined();
    // 1件でも修正版なしまたはEOLの場合は「移行」を含み「更新」を含まないこと
    expect(cveCheck?.recommendation).toContain('移行');
    expect(cveCheck?.recommendation).not.toContain('更新');
    expect(cveCheck?.recommendation).toContain('Angularなどへの移行');
    // CVSSフォールバック値表示の検証: 不正確な「CVSS: 6」を含まず一次情報通りの「重大度: MEDIUM」を表示すること
    expect(cveCheck?.observed).not.toContain('CVSS: 6');
    expect(cveCheck?.observed).toContain('重大度: MEDIUM');
  });
});

describe('HTTPレスポンスヘッダーキャッシュ セキュリティ & URLサニタイズ', () => {
  it('許可リスト方式により機密ヘッダー(set-cookie, authorization等)が除外され、許可ヘッダー(server, csp等)のみが保持されること', async () => {
    // service-worker からエクスポートされた関数をテスト
    const { filterAndSanitizeHeaders } = await import('../src/background/service-worker');
    
    const inputHeaders = {
      'Set-Cookie': ['session=SECRET_TOKEN; Path=/; HttpOnly', 'canary=CANARY_VAL'],
      'authorization': ['Bearer eyJhbGciOi...'],
      'x-auth-token': ['SUPER_SECRET'],
      'Location': ['/redirect?token=SECRET_CANARY'],
      'Server': ['Apache/2.4.58'],
      'Content-Security-Policy': ["default-src 'self'"],
      'Strict-Transport-Security': ['max-age=31536000'],
      'X-Powered-By': ['PHP/8.2.14'],
      'CF-Ray': ['8923489234'],
    };

    const sanitized = filterAndSanitizeHeaders(inputHeaders);

    // 許可ヘッダーは保持される
    expect(sanitized['server']).toEqual(['Apache/2.4.58']);
    expect(sanitized['content-security-policy']).toEqual(["default-src 'self'"]);
    expect(sanitized['strict-transport-security']).toEqual(['max-age=31536000']);
    expect(sanitized['x-powered-by']).toEqual(['PHP/8.2.14']);
    expect(sanitized['cf-ray']).toEqual(['8923489234']);

    // 機密・認証ヘッダーはキーごと破棄される (置換やREDACTEDではなく完全除外)
    expect(sanitized['set-cookie']).toBeUndefined();
    expect(sanitized['authorization']).toBeUndefined();
    expect(sanitized['x-auth-token']).toBeUndefined();
    expect(sanitized['location']).toBeUndefined();
    expect(Object.keys(sanitized)).not.toContain('set-cookie');
    expect(Object.keys(sanitized)).not.toContain('authorization');
  });

  it('キャッシュに保存するURLからクエリパラメータとフラグメントが完全に除去され origin + pathname のみになること', async () => {
    const { sanitizeUrlForCache } = await import('../src/background/service-worker');

    expect(sanitizeUrlForCache('https://example.com/login?token=SECRET_CANARY#section')).toBe('https://example.com/login');
    expect(sanitizeUrlForCache('http://localhost:3000/api/v1/user?id=123&auth=abc')).toBe('http://localhost:3000/api/v1/user');
    expect(sanitizeUrlForCache('https://sub.domain.jp:8080/path/to/page?q=test#frag')).toBe('https://sub.domain.jp:8080/path/to/page');

    // 4-3 & 6: 指定5入力の完全検証
    expect(sanitizeUrlForCache('http://example.com:8080/path?a=1#b')).toBe('http://example.com:8080/path');
    expect(sanitizeUrlForCache('file:///tmp/x?token=1#frag')).toBe('file:///tmp/x');
    expect(sanitizeUrlForCache('about:blank?token=1')).toBe('about:blank');
    expect(sanitizeUrlForCache('data:text/html,x?token=1')).toBe('data:text/html,x');
    expect(sanitizeUrlForCache('data:text/html,<h1>test</h1>?token=1')).toBe('data:text/html,<h1>test</h1>');
    expect(sanitizeUrlForCache('bad-url-string?token=1#frag')).toBe('bad-url-string');

    // userinfo (ユーザー名・パスワード) 付きURLの検証 (origin + pathname により自動ストリップ)
    expect(sanitizeUrlForCache('https://user:secretpass@example.com:8443/secure/path?token=CANARY#section'))
      .toBe('https://example.com:8443/secure/path');
  });

  it('sessionストレージからの復元時にも許可リストとURLサニタイズが再適用されること', async () => {
    const { sanitizeRestoredHeaderEntry } = await import('../src/background/service-worker');

    const rawStoredEntry = {
      url: 'https://example.com/profile?session_token=CANARY_STOKEN#anchor',
      headers: {
        'set-cookie': ['canary_cookie=CANARY_VALUE'],
        'authorization': ['Bearer CANARY_AUTH'],
        'server': ['nginx/1.24.0'],
      },
      updatedAt: 123456789,
    };

    const restored = sanitizeRestoredHeaderEntry(rawStoredEntry);

    expect(restored.url).toBe('https://example.com/profile');
    expect(restored.headers['server']).toEqual(['nginx/1.24.0']);
    expect(restored.headers['set-cookie']).toBeUndefined();
    expect(restored.headers['authorization']).toBeUndefined();
    expect(restored.observed).toBe(true);
  });

  it('A6: observedフィールドを持たない古いキャッシュエントリ(v1.6.4以前)の復元時にも安全にobserved:trueが付与されサニタイズされること', async () => {
    const { sanitizeRestoredHeaderEntry } = await import('../src/background/service-worker');

    // 1.6.4 以前の形式（observed フィールド未定義、クエリ付きURL、未サニタイズヘッダー）
    const legacyEntry = {
      url: 'https://example.com/dashboard?legacy_auth=SECRET_TOKEN#tab1',
      headers: {
        'server': ['nginx/1.24.0'],
        'set-cookie': ['old_cookie=SECRET_COOKIE'],
        'x-powered-by': ['Express'],
      },
      updatedAt: 1600000000000,
    };

    const restored = sanitizeRestoredHeaderEntry(legacyEntry);
    expect(restored.url).toBe('https://example.com/dashboard');
    expect(restored.headers['server']).toEqual(['nginx/1.24.0']);
    expect(restored.headers['x-powered-by']).toEqual(['Express']);
    expect(restored.headers['set-cookie']).toBeUndefined();
    expect(restored.observed).toBe(true);
  });

  it('A1: Service Workerのキャッシュ経由で x-nextjs-cache を含むレスポンスから Node.js が正しく推論されること', async () => {
    const { filterAndSanitizeHeaders } = await import('../src/background/service-worker');

    // レスポンスヘッダーが許可リスト・サニタイズ処理を経てキャッシュされる
    const rawHeaders = {
      'x-nextjs-cache': ['HIT'],
    };
    const cachedHeaders = filterAndSanitizeHeaders(rawHeaders);

    const deps = createMockDeps({
      tab: { id: 102, url: 'https://example.com/' },
      fetchDomSignals: vi.fn().mockResolvedValue(
        createMockDomSignals({
          scriptUrls: ['https://example.com/_next/static/chunks/main.js'],
        })
      ),
      getCachedHeaders: vi.fn().mockResolvedValue({
        url: 'https://example.com/',
        headers: cachedHeaders,
        observed: true,
      }),
    });

    const report = await executeInspection(deps);
    
    // Next.js が直接検出されていること
    const nextTech = report.technologies.find((t) => t.technology === 'Next.js');
    expect(nextTech).toBeDefined();

    // x-nextjs-cache ヘッダーがキャッシュに残ることで、サーバーサイド稼働と判定され Node.js が連動推論されること
    const nodeTech = report.technologies.find((t) => t.technology === 'Node.js');
    expect(nodeTech).toBeDefined();
    expect(nodeTech?.detectionMethod).toBe('inferred');
  });

  it('3-3: 許可リスト (ALLOWED_RESPONSE_HEADERS) の期待値テスト (包含・除外ヘッダーの網羅性)', async () => {
    const { ALLOWED_RESPONSE_HEADERS } = await import('../src/background/service-worker');

    // 含まれるべきヘッダー
    const expectedIncluded = [
      'x-nextjs-cache',
      'x-nitro-cache',
      'content-security-policy',
      'strict-transport-security',
      'server',
      'x-powered-by',
      'x-frame-options',
    ];
    for (const h of expectedIncluded) {
      expect(ALLOWED_RESPONSE_HEADERS.has(h), `ヘッダー "${h}" が許可リストに含まれていません`).toBe(true);
    }

    // 含まれてはならない機密・認証・危険ヘッダー
    const expectedExcluded = [
      'set-cookie',
      'set-cookie2',
      'authorization',
      'location',
      'www-authenticate',
      'proxy-authenticate',
      'authentication-info',
    ];
    for (const h of expectedExcluded) {
      expect(ALLOWED_RESPONSE_HEADERS.has(h), `機密ヘッダー "${h}" が誤って許可リストに含まれています`).toBe(false);
    }
  });

  it('ヘッダー観測判定がキャッシュヘッダー数に依存せず、許可ヘッダー0個でも観測済み(complete)と判定されること', async () => {
    const deps = createMockDeps({
      getCachedHeaders: vi.fn().mockResolvedValue({
        url: 'https://example.com/',
        headers: {},
        observed: true,
      }),
    });

    const report = await executeInspection(deps);
    expect(report.coverage?.headers).toBe('complete');
    expect(report.coverage?.details?.unobservedPreScan).toBe(false);
  });

  it('IMPL-02: キャッシュの origin がタブと異なる場合に未観測扱いになること', async () => {
    const deps = createMockDeps({
      tab: { id: 101, url: 'https://example.com/page' },
      getCachedHeaders: vi.fn().mockResolvedValue({
        url: 'https://another-domain.com/page',
        headers: {
          'strict-transport-security': ['max-age=31536000'],
          'x-frame-options': ['DENY'],
        },
        observed: true,
      }),
    });

    const report = await executeInspection(deps);
    const headerChecks = report.securityChecks.filter((c) =>
      /^SEC-(HSTS|CSP|XFO|XCTO|REF|PERM|CORS|DISC)/.test(c.checkId)
    );
    expect(headerChecks.length).toBeGreaterThan(0);
    expect(headerChecks.every((c) => c.status === 'unknown' && c.severity === 'info')).toBe(true);
    expect(report.summary.requiresAttentionCount).toBe(0);
    expect(report.coverage?.headers).toBe('partial');
    expect(report.coverage?.details?.unobservedPreScan).toBe(true);
  });

  it('IMPL-02: 同一 origin・別パスでは観測済みのままであること', async () => {
    const deps = createMockDeps({
      tab: { id: 101, url: 'https://example.com/dashboard' },
      getCachedHeaders: vi.fn().mockResolvedValue({
        url: 'https://example.com/login',
        headers: {
          'strict-transport-security': ['max-age=31536000'],
          'x-frame-options': ['DENY'],
        },
        observed: true,
      }),
    });

    const report = await executeInspection(deps);
    const hstsCheck = report.securityChecks.find((c) => c.checkId.startsWith('SEC-HSTS-'));
    expect(hstsCheck).toBeDefined();
    expect(hstsCheck?.status).toBe('pass');
    expect(report.coverage?.headers).toBe('complete');
  });
});
