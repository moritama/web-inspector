import * as fs from 'fs';
import * as path from 'path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  executeInspection,
  fetchDomSignals,
  getInspectedCookies,
  handleRuntimeMessage,
  InspectionDependencies,
  resolveTopLevelSite,
} from '../src/background/service-worker';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderSecurityCheckRowHtml } from '../src/popup/render';
import {
  generateFindingIdFromCheck,
  generateLegacyFindingIdFromCheck,
} from '../src/shared/identity';
import {
  DomSignals,
  FindingException,
  InspectedCookieInfo,
  InspectionReport,
} from '../src/shared/types';
import {
  getAllFindingExceptions,
  STORAGE_KEY_EXCEPTIONS,
} from '../src/storage/exceptions';
import {
  enforceReportStorageLimits,
  estimateJsonByteSize,
  getAllHistoryReports,
  saveReportToHistory,
  STORAGE_KEY_HISTORY,
} from '../src/storage/history';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

const fixtureDb = rawFixtureDb as unknown as AdvisoryDatabase;

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
    // 重大度の値はDBの更新で変わるため、ラベルで表示されていることだけを確かめる
    expect(cveCheck?.observed).toMatch(/重大度: (LOW|MEDIUM|HIGH|CRITICAL)/);
  });

  it('MAIN world から取得した不正な実行時バージョンおよび未知のフレームワークマーカーが無害化・除去されること (IMPL-04)', async () => {
    let capturedDomSignals: any = null;
    const deps = createMockDeps({
      fetchDomSignals: vi.fn().mockImplementation(async (_tabId, _url) => {
        const dom = createMockDomSignals();
        capturedDomSignals = dom;
        return dom;
      }),
      fetchRuntimeVersions: vi.fn().mockResolvedValue({
        versions: {
          jquery: 'custom-build', // 書式不一致 -> null
          vue: '3.4.1', // 正常 -> '3.4.1'
          react: 'A'.repeat(50), // 32文字超え -> null
          malicious: '1.0.0<script>alert(1)</script>', // 不正文字 -> null
          num: 123 as any, // string 以外 -> null
        },
        frameworkMarkers: [
          '__reactContainer$', // 既知 -> 保持
          '__evil_marker__', // 未知 -> 除外
          '__vue_app__', // 既知 -> 保持
        ],
      }),
    });

    await executeInspection(deps);

    expect(capturedDomSignals.runtimeVersions).toEqual({
      jquery: null,
      vue: '3.4.1',
      react: null,
      malicious: null,
      num: null,
    });
    expect(capturedDomSignals.domMarkers).toContain('__reactContainer$');
    expect(capturedDomSignals.domMarkers).toContain('__vue_app__');
    expect(capturedDomSignals.domMarkers).not.toContain('__evil_marker__');
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
      // ライブラリの EOL・脆弱性はDBの更新で変わるため、ヘッダー以外の要因で要確認が増えないようにする
      fetchDomSignals: vi.fn().mockResolvedValue(createMockDomSignals({ metaTags: [], scriptUrls: [] })),
      fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
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

  describe('T03 (SPEC-13): 脆弱性チェック (SEC-CVE-*) の 4 段階重大度と KEV 昇格', () => {
    afterEach(() => {
      setTestAdvisoryDatabase(null);
    });

    it('KEV エントリ (CVE-2020-11023) にヒットしたときに、セキュリティ診断の重大度が critical になり critical 件数が集計されること', async () => {
      setTestAdvisoryDatabase(fixtureDb);

      const deps = createMockDeps({
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            metaTags: [],
            scriptUrls: ['https://code.jquery.com/jquery-3.4.1.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.4.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://example.com/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-JQUERY');
      expect(cveCheck).toBeDefined();
      expect(cveCheck?.severity).toBe('critical');
      expect(cveCheck?.description).toContain('悪用確認済み（CISA KEV）');
      expect(report.summary.securityFindings.critical).toBeGreaterThanOrEqual(1);
    });

    it('CVSS 9.0 (critical、KEV でない) のエントリだけにヒットしたときに、重大度が critical になること', async () => {
      setTestAdvisoryDatabase({
        version: '2026.10-test',
        generatedAt: new Date().toISOString(),
        libraries: {
          jquery: {
            aliases: ['jquery'],
            versions: [
              {
                range: '>= 3.4.0, < 3.5.0',
                cve: 'CVE-2026-9000',
                cvssScore: 9.0,
                severity: 'critical',
                title: 'Critical non-KEV vulnerability in jQuery',
                fixedVersion: '3.5.0',
                fixStatus: 'fixed',
                kev: false,
              },
            ],
            eol: [],
          },
        },
      });

      const deps = createMockDeps({
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            metaTags: [],
            scriptUrls: ['https://code.jquery.com/jquery-3.4.1.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.4.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://example.com/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-JQUERY');
      expect(cveCheck).toBeDefined();
      expect(cveCheck?.severity).toBe('critical');
      expect(report.summary.securityFindings.critical).toBe(1);
    });

    it('CVSS 3.1 (low、KEV でない) のエントリだけにヒットしたときに、重大度が low になること', async () => {
      setTestAdvisoryDatabase({
        version: '2026.10-test',
        generatedAt: new Date().toISOString(),
        libraries: {
          jquery: {
            aliases: ['jquery'],
            versions: [
              {
                range: '>= 3.4.0, < 3.5.0',
                cve: 'CVE-2026-3100',
                cvssScore: 3.1,
                severity: 'low',
                title: 'Low severity non-KEV vulnerability in jQuery',
                fixedVersion: '3.5.0',
                fixStatus: 'fixed',
                kev: false,
              },
            ],
            eol: [],
          },
        },
      });

      const deps = createMockDeps({
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            metaTags: [],
            scriptUrls: ['https://code.jquery.com/jquery-3.4.1.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.4.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://example.com/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-JQUERY');
      expect(cveCheck).toBeDefined();
      expect(cveCheck?.severity).toBe('low');
    });

    it('同一ライブラリの複数バージョンが検出された場合、インスタンスごとに SEC-CVE-* / SEC-EOL-* が生成され、例外 ID (findingId) にバージョンが含まれること (T08 / SPEC-10)', async () => {
      const deps = createMockDeps({
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            metaTags: [],
            scriptUrls: [
              'https://example.com/js/jquery-1.12.4.min.js',
              'https://example.com/js/jquery-2.2.4.min.js',
              'https://example.com/js/jquery-3.7.1.min.js',
            ],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.7.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://example.com/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const jqCveChecks = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-CVE-JQUERY'));
      const jqEolChecks = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-EOL-JQUERY'));

      // 1.12.4 と 2.2.4 の 2 インスタンスそれぞれに対して CVE と EOL の診断結果が生成されること
      expect(jqCveChecks.length).toBe(2);
      expect(jqEolChecks.length).toBe(2);

      // 各診断結果の findingId にバージョン番号が含まれ、かつ異なる findingId であること
      expect(jqCveChecks[0].findingId).toContain('1.12.4');
      expect(jqCveChecks[1].findingId).toContain('2.2.4');
      expect(jqCveChecks[0].findingId).not.toBe(jqCveChecks[1].findingId);

      expect(jqEolChecks[0].findingId).toContain('1.12.4');
      expect(jqEolChecks[1].findingId).toContain('2.2.4');
      expect(jqEolChecks[0].findingId).not.toBe(jqEolChecks[1].findingId);
    });

    it('v1.7.1 T01: 既知脆弱性 (SEC-CVE-*) の観測値で括弧が対になっており Markdown 出力やポップアップ描画でも閉じ括弧が欠けないこと、および summary 件数が一致すること', async () => {
      setTestAdvisoryDatabase(fixtureDb);

      const deps = createMockDeps({
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            metaTags: [],
            scriptUrls: ['https://code.jquery.com/jquery-3.4.1.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.4.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://portal.example.test/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-JQUERY');
      expect(cveCheck).toBeDefined();

      const observed = cveCheck!.observed;
      const openHalf = (observed.match(/\(/g) || []).length;
      const closeHalf = (observed.match(/\)/g) || []).length;
      const openFull = (observed.match(/（/g) || []).length;
      const closeFull = (observed.match(/）/g) || []).length;
      expect(openHalf).toBeGreaterThan(0);
      expect(openHalf).toBe(closeHalf);
      expect(openFull).toBe(closeFull);

      // Markdown 出力の表セル内でも観測値の閉じ括弧が欠けないこと
      const md = generateMarkdownReport(report);
      expect(md).toContain(`\`${observed}\``);

      // ポップアップの行 HTML でも観測値の閉じ括弧が欠けないこと
      const popupRowHtml = renderSecurityCheckRowHtml(cveCheck!);
      expect(popupRowHtml).toContain(observed);

      // summary.securityFindings の CRITICAL〜LOW 合計が requiresAttentionCount と一致すること
      const sf = report.summary.securityFindings;
      const severitySum = (sf.critical ?? 0) + sf.high + sf.medium + sf.low;
      expect(severitySum).toBe(report.summary.requiresAttentionCount);
    });
  });

  describe('T10 (IMPL-05, IMPL-06, IMPL-07, IMPL-09): メッセージ検証・履歴容量・URLマスク・許容設定ID移行', () => {
    it('IMPL-05: content script を装った sender（sender.tab あり、sender.url が https のページ）からの履歴削除メッセージが拒否され、履歴が残ること', async () => {
      const store: Record<string, unknown> = {};
      const extId = 'test-extension-id';

      (globalThis as any).chrome = {
        runtime: {
          id: extId,
          getURL: (path: string) => `chrome-extension://${extId}/${path.replace(/^\//, '')}`,
        },
        storage: {
          local: {
            get: vi.fn(async (key: string) => ({ [key]: store[key] })),
            set: vi.fn(async (items: Record<string, unknown>) => {
              Object.assign(store, items);
            }),
            remove: vi.fn(async (key: string) => {
              delete store[key];
            }),
          },
        },
      };

      const existingReport = await executeInspection(createMockDeps());
      await saveReportToHistory(existingReport);
      expect((await getAllHistoryReports()).length).toBe(1);

      const contentScriptSender = {
        id: extId,
        tab: { id: 101 } as chrome.tabs.Tab,
        url: 'https://example.com/malicious-page',
      } as chrome.runtime.MessageSender;

      const sendResponseClear = vi.fn();
      const handledClear = handleRuntimeMessage(
        { type: 'CLEAR_HISTORY' },
        contentScriptSender,
        sendResponseClear
      );
      expect(handledClear).toBe(false);
      expect(sendResponseClear).toHaveBeenCalledWith(
        expect.objectContaining({ success: false })
      );

      const sendResponseDelete = vi.fn();
      const handledDelete = handleRuntimeMessage(
        { type: 'DELETE_HISTORY_ITEM', id: existingReport.id },
        contentScriptSender,
        sendResponseDelete
      );
      expect(handledDelete).toBe(false);
      expect(sendResponseDelete).toHaveBeenCalledWith(
        expect.objectContaining({ success: false })
      );

      // 履歴が消されずに残っていること
      const remaining = await getAllHistoryReports();
      expect(remaining.length).toBe(1);
      expect(remaining[0].id).toBe(existingReport.id);
    });

    it('IMPL-05: 未知のメッセージに対してリスナーが false を返し、不正な形のメッセージも拒否すること', () => {
      const extId = 'test-extension-id';
      (globalThis as any).chrome = {
        runtime: {
          id: extId,
          getURL: (path: string) => `chrome-extension://${extId}/${path.replace(/^\//, '')}`,
        },
      };

      const privilegedSender = {
        id: extId,
        url: `chrome-extension://${extId}/popup.html`,
      } as chrome.runtime.MessageSender;

      const sendResponse = vi.fn();
      expect(handleRuntimeMessage({ type: 'UNKNOWN_MESSAGE_TYPE' }, privilegedSender, sendResponse)).toBe(false);
      expect(handleRuntimeMessage(null, privilegedSender, sendResponse)).toBe(false);
      expect(sendResponse).not.toHaveBeenCalled();

      // 既知の type だが必須フィールド id が欠落している場合
      const invalidIdResponse = vi.fn();
      expect(
        handleRuntimeMessage({ type: 'DELETE_HISTORY_ITEM', id: '' }, privilegedSender, invalidIdResponse)
      ).toBe(false);
      expect(invalidIdResponse).toHaveBeenCalledWith(expect.objectContaining({ success: false }));
    });

    it('IMPL-06: chrome.storage.local.set が例外を投げるモックでも、調査結果が返り、保存失敗の通知が出ること', async () => {
      (globalThis as any).chrome = {
        storage: {
          local: {
            get: vi.fn().mockResolvedValue({}),
            set: vi.fn().mockRejectedValue(new Error('QuotaExceededError: storage is full')),
          },
        },
      };

      const deps = createMockDeps({
        saveReport: saveReportToHistory,
      });

      const report = await executeInspection(deps);
      expect(report).toBeDefined();
      expect(report.hostname).toBe('example.com');
      expect(report.historySaveFailed).toBe(true);
      expect(report.storageWarning).toBeTruthy();
      expect(report.storageWarning).toContain('履歴の保存に失敗しました');
    });

    it('IMPL-06: 2 件の調査を同時に保存しても、直列化キューにより両方が履歴に残ること', async () => {
      const store: Record<string, unknown> = {};
      (globalThis as any).chrome = {
        storage: {
          local: {
            get: vi.fn(async (key: string) => {
              await new Promise((r) => setTimeout(r, 15));
              return { [key]: store[key] };
            }),
            set: vi.fn(async (items: Record<string, unknown>) => {
              await new Promise((r) => setTimeout(r, 15));
              Object.assign(store, items);
            }),
          },
        },
      };

      const rep1 = await executeInspection(
        createMockDeps({ tab: { id: 1, url: 'https://site-one.example.com/' } })
      );
      const rep2 = await executeInspection(
        createMockDeps({ tab: { id: 2, url: 'https://site-two.example.com/' } })
      );

      await Promise.all([saveReportToHistory(rep1), saveReportToHistory(rep2)]);

      const saved = await getAllHistoryReports();
      expect(saved.length).toBe(2);
      const ids = saved.map((r) => r.id);
      expect(ids).toContain(rep1.id);
      expect(ids).toContain(rep2.id);
    });

    it('IMPL-06: 1 技術あたりの evidence が 20 件までに切り詰められ、合計容量超過時は古い履歴から削除されること', async () => {
      const store: Record<string, unknown> = {};
      (globalThis as any).chrome = {
        storage: {
          local: {
            get: vi.fn(async (key: string) => ({ [key]: store[key] })),
            set: vi.fn(async (items: Record<string, unknown>) => {
              Object.assign(store, items);
            }),
          },
        },
      };

      const baseReport = await executeInspection(createMockDeps());
      const manyEvidences = Array.from({ length: 30 }, (_, i) => ({
        type: 'script-url' as const,
        name: `Script ${i}`,
        value: `https://example.com/js/chunk-${i}.js?secret=token${i}#frag`,
        source: `https://example.com/page?secret=token${i}#frag`,
        weight: 50,
      }));
      const reportWithManyEvidences: InspectionReport = {
        ...baseReport,
        id: 'rep_many_evidences',
        technologies: baseReport.technologies.map((t, idx) =>
          idx === 0 ? { ...t, evidence: manyEvidences } : t
        ),
      };

      // 1件分は収まるが2件分の合計は超える上限を指定して、古い履歴が削除されることも検証
      const oldReport: InspectionReport = {
        ...baseReport,
        id: 'rep_old',
      };
      const singleReportBytes = estimateJsonByteSize([
        enforceReportStorageLimits(reportWithManyEvidences),
      ]);
      await saveReportToHistory(oldReport, 50, singleReportBytes * 3);
      await saveReportToHistory(reportWithManyEvidences, 50, singleReportBytes + 200);

      const saved = (store[STORAGE_KEY_HISTORY] as InspectionReport[]) || [];
      expect(saved.length).toBe(1);
      expect(saved[0].id).toBe('rep_many_evidences');
      expect(saved[0].technologies[0].evidence.length).toBe(20);
      expect(JSON.stringify(saved[0])).not.toContain('secret=token');
    });

    it('IMPL-07: https://example.com/a?token=x#y を調査した履歴に token=x が含まれないこと', async () => {
      const store: Record<string, unknown> = {};
      (globalThis as any).chrome = {
        storage: {
          local: {
            get: vi.fn(async (key: string) => ({ [key]: store[key] })),
            set: vi.fn(async (items: Record<string, unknown>) => {
              Object.assign(store, items);
            }),
          },
        },
      };

      const deps = createMockDeps({
        tab: { id: 101, url: 'https://example.com/a?token=x#y' },
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            url: 'https://example.com/a?token=x#y',
            scriptUrls: ['https://example.com/app.js?token=x#y'],
          })
        ),
        saveReport: saveReportToHistory,
      });

      const report = await executeInspection(deps);
      expect(report.url).toBe('https://example.com/a');
      expect(JSON.stringify(report)).not.toContain('token=x');

      const savedHistory = await getAllHistoryReports();
      expect(savedHistory.length).toBe(1);
      expect(savedHistory[0].url).toBe('https://example.com/a');
      expect(JSON.stringify(savedHistory)).not.toContain('token=x');
    });

    it('IMPL-09: クエリだけが違う URL でも許容設定が効き続け、v1.6.6 形式の許容設定が移行後も効くこと', async () => {
      const legacyFindingId = generateLegacyFindingIdFromCheck(
        'SEC-HSTS-01',
        'https://example.com/a?token=1',
        'HSTS (Strict-Transport-Security)'
      );
      const store: Record<string, unknown> = {
        [STORAGE_KEY_EXCEPTIONS]: [
          {
            id: 'ex_legacy_hsts',
            findingId: legacyFindingId,
            targetUrl: 'https://example.com/a?token=1',
            status: 'accepted',
            reason: 'v1.6.6 で登録した許容設定',
            createdAt: '2026-10-01T00:00:00Z',
          } satisfies FindingException,
        ],
      };

      (globalThis as any).chrome = {
        storage: {
          local: {
            get: vi.fn(async (key: string) => ({ [key]: store[key] })),
            set: vi.fn(async (items: Record<string, unknown>) => {
              Object.assign(store, items);
            }),
          },
        },
      };

      const deps = createMockDeps({
        tab: { id: 101, url: 'https://example.com/a?token=2#section' },
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://example.com/a?token=2#section',
          headers: {},
          observed: true,
        }),
        getAllFindingExceptions,
      });

      const report = await executeInspection(deps);
      const hstsCheck = report.securityChecks.find((c) => c.checkId === 'SEC-HSTS-01');
      expect(hstsCheck).toBeDefined();
      expect(hstsCheck?.exceptionStatus).toBe('accepted');
      expect(hstsCheck?.findingId).toBe(
        generateFindingIdFromCheck('SEC-HSTS-01', 'https://example.com/a?token=2')
      );

      // ストレージ内の許容設定も新しい findingId に移行され、targetUrl からクエリが除去されていること
      const migratedExceptions = store[STORAGE_KEY_EXCEPTIONS] as FindingException[];
      expect(migratedExceptions[0].findingId).toBe(
        generateFindingIdFromCheck('SEC-HSTS-01', 'https://example.com')
      );
      expect(migratedExceptions[0].targetUrl).toBe('https://example.com/a');
    });
  });

  describe('T11: 必要なときだけ注入、CHIPS、Cookie の重複除去 (IMPL-08, IMPL-11, IMPL-12, DOC-08, D6)', () => {
    it('IMPL-08 / D6: public/manifest.json に content_scripts が無く、permissions と host_permissions は v1.6.6.1 と同じであること', () => {
      const manifestPath = path.resolve(__dirname, '../public/manifest.json');
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));

      expect('content_scripts' in manifest).toBe(false);
      expect(new Set(manifest.permissions)).toEqual(
        new Set(['activeTab', 'storage', 'scripting', 'webRequest', 'cookies'])
      );
      expect(manifest.host_permissions).toEqual(['<all_urls>']);
    });

    it('DOC-08: PRIVACY_POLICY.md に「常時」「全ページに注入・配置」に当たる記述が残っておらず、オンデマンド注入とクエリマスクが反映されていること', () => {
      const ppPath = path.resolve(__dirname, '../PRIVACY_POLICY.md');
      const ppContent = fs.readFileSync(ppPath, 'utf-8');

      expect(ppContent).not.toContain('Content scripts are deployed across all visited pages');
      expect(ppContent).not.toContain('Content scripts are deployed to all visited pages');
      expect(ppContent).not.toContain('コンテンツスクリプトはすべてのページに配置されますが');
      expect(ppContent).not.toContain('クエリ文字列は含まれます');
      expect(ppContent).not.toContain('query strings are included');

      expect(ppContent).toContain('chrome.scripting.executeScript');
      expect(ppContent).toContain('オンデマンド');
    });

    it('IMPL-08: fetchDomSignals が調査時に chrome.scripting.executeScript で content-script.js を注入し、同じページを2回調査しても evidence が重複しないこと', async () => {
      const mockSignals = createMockDomSignals({
        cookiesFromDocument: ['laravel_session'],
      });
      const executeScriptMock = vi.fn().mockResolvedValue([{ result: undefined }]);
      const sendMessageMock = vi.fn().mockResolvedValue(mockSignals);

      (globalThis as any).chrome = {
        scripting: {
          executeScript: executeScriptMock,
        },
        tabs: {
          sendMessage: sendMessageMock,
        },
      };

      const signals1 = await fetchDomSignals(101, 'https://example.com/');
      expect(executeScriptMock).toHaveBeenCalledTimes(1);
      expect(executeScriptMock).toHaveBeenCalledWith({
        target: { tabId: 101 },
        files: ['content/content-script.js'],
      });
      expect(sendMessageMock).toHaveBeenCalledWith(101, { type: 'EXTRACT_DOM_SIGNALS' });
      expect(signals1.title).toBe('Example Domain');

      // 同じページを2回調査しても evidence が重複しないことを確認
      const deps = createMockDeps({
        fetchDomSignals: () => fetchDomSignals(101, 'https://example.com/'),
      });
      const report1 = await executeInspection(deps);
      const report2 = await executeInspection(deps);

      const laravel1 = report1.technologies.find((t) => t.technology === 'Laravel');
      const laravel2 = report2.technologies.find((t) => t.technology === 'Laravel');
      expect(laravel1).toBeDefined();
      expect(laravel2).toBeDefined();
      expect(laravel1?.evidence.length).toBe(1);
      expect(laravel2?.evidence.length).toBe(1);
    });

    it('IMPL-11: getInspectedCookies が通常の取得に加えて partitionKey: { topLevelSite } 付きでも getAll を呼び出し、Partitioned 属性付きの Cookie (CHIPS) を評価すること', async () => {
      expect(resolveTopLevelSite('https://app.sub.example.co.jp/dashboard')).toBe(
        'https://example.co.jp'
      );
      expect(resolveTopLevelSite('https://sub.example.com/login')).toBe('https://example.com');

      const getAllMock = vi.fn(async (details: { url: string; partitionKey?: { topLevelSite: string } }) => {
        if (details.partitionKey) {
          return [
            {
              name: '__Host-chips_session',
              value: 'secret-chips-val',
              domain: 'sub.example.com',
              path: '/',
              secure: true,
              httpOnly: false, // 認証系 CHIPS Cookie で HttpOnly 未設定 -> SEC-COOKIE-HTTPONLY 検出対象
              sameSite: 'no_restriction',
              session: true,
              hostOnly: true,
              partitionKey: { topLevelSite: details.partitionKey.topLevelSite },
            },
          ];
        }
        return [
          {
            name: 'normal_pref',
            value: 'dark',
            domain: 'sub.example.com',
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            session: false,
            hostOnly: true,
          },
        ];
      });

      (globalThis as any).chrome = {
        cookies: {
          getAll: getAllMock,
        },
      };

      const targetUrl = 'https://sub.example.com/app';
      const cookies = await getInspectedCookies(targetUrl);

      expect(getAllMock).toHaveBeenCalledTimes(2);
      expect(getAllMock).toHaveBeenNthCalledWith(1, { url: targetUrl });
      expect(getAllMock).toHaveBeenNthCalledWith(2, {
        url: targetUrl,
        partitionKey: { topLevelSite: 'https://example.com' },
      });

      expect(cookies).toHaveLength(2);
      const chipsCookie = cookies.find((c) => c.name === '__Host-chips_session');
      expect(chipsCookie).toBeDefined();
      expect(chipsCookie?.partitioned).toBe(true);
      expect(chipsCookie?.partitionKey).toBe('https://example.com');

      // executeInspection で Partitioned (CHIPS) Cookie のセキュリティ評価が行われることを確認
      const deps = createMockDeps({
        tab: { id: 101, url: targetUrl },
        getInspectedCookies: () => getInspectedCookies(targetUrl),
      });
      const report = await executeInspection(deps);
      const evaluatedChips = report.cookies.find((c) => c.name === '__Host-chips_session');
      expect(evaluatedChips).toBeDefined();
      expect(evaluatedChips?.partitioned).toBe(true);
      expect(evaluatedChips?.partitionKey).toBe('https://example.com');

      const httpOnlyCheck = report.securityChecks.find((c) => c.checkId === 'SEC-COOKIE-HTTPONLY');
      expect(httpOnlyCheck).toBeDefined();
      expect(httpOnlyCheck?.observed).toContain('__Host-chips_session');
    });
  });

  describe('v1.7.1 T06: Content Script 収集失敗時の完全性 (partial) と domItemCount の拡張', () => {
    it('Content Script の収集を失敗させたモック（sendMessage 失敗 / fetchDomSignals 失敗 / 途中失敗）で、完全性が「部分的 (partial)」になり理由が出ること', async () => {
      // 1. chrome.tabs.sendMessage が例外を投げた場合 (fetchDomSignals 経由)
      (globalThis as any).chrome = {
        scripting: {
          executeScript: vi.fn().mockResolvedValue([{ result: undefined }]),
        },
        tabs: {
          sendMessage: vi.fn().mockRejectedValue(new Error('Could not establish connection')),
        },
      };

      const fallbackSignals = await fetchDomSignals(101, 'https://app.example.test/');
      expect(fallbackSignals.collectionPartial).toBe(true);
      expect(fallbackSignals.collectionErrors?.[0]).toContain('Could not establish connection');

      const mockHeaders = vi.fn().mockResolvedValue({
        url: 'https://app.example.test/',
        headers: {
          server: ['Apache/2.4.58 (Ubuntu)'],
        },
      });

      const reportFromSendMessageFail = await executeInspection(
        createMockDeps({
          tab: { id: 101, url: 'https://app.example.test/' },
          getCachedHeaders: mockHeaders,
          fetchDomSignals: () => fetchDomSignals(101, 'https://app.example.test/'),
        })
      );
      expect(reportFromSendMessageFail.coverage?.headers).toBe('complete');
      expect(reportFromSendMessageFail.coverage?.overallStatus).toBe('partial');
      expect(reportFromSendMessageFail.coverage?.dom).toBe('partial');
      expect(reportFromSendMessageFail.coverage?.details?.partialReasons?.length).toBeGreaterThan(0);
      const md1 = generateMarkdownReport(reportFromSendMessageFail);
      expect(md1).toContain('一部制限あり (Partial)');
      expect(md1).toContain('**部分的となった理由:**');

      // 2. deps.fetchDomSignals 自体が reject した場合
      const reportFromRejectedDep = await executeInspection(
        createMockDeps({
          tab: { id: 101, url: 'https://app.example.test/' },
          getCachedHeaders: mockHeaders,
          fetchDomSignals: vi.fn().mockRejectedValue(new Error('Frame was detached during scan')),
        })
      );
      expect(reportFromRejectedDep.coverage?.headers).toBe('complete');
      expect(reportFromRejectedDep.coverage?.overallStatus).toBe('partial');
      expect(reportFromRejectedDep.coverage?.dom).toBe('partial');
      expect(
        reportFromRejectedDep.coverage?.details?.partialReasons?.some((r) =>
          r.includes('Frame was detached during scan')
        )
      ).toBe(true);
    });

    it('executeInspection の domItemCount が metaTags と scriptUrls に加えて domMarkers・スタイルシート・htmlSnippets を含めて集計されること', async () => {
      const deps = createMockDeps({
        tab: { id: 101, url: 'https://app.example.test/' },
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://app.example.test/',
          headers: {
            server: ['Apache/2.4.58 (Ubuntu)'],
          },
        }),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: {},
          frameworkMarkers: [],
        }),
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            url: 'https://app.example.test/',
            metaTags: [{ name: 'generator', content: 'WordPress 6.4.2' }],
            scriptUrls: ['https://app.example.test/js/app.js'],
            linkUrls: [{ rel: 'stylesheet', href: 'https://app.example.test/css/style.css' }],
            domMarkers: ['[ng-version]', '_nghost-'],
            htmlSnippets: ['container flex'],
          })
        ),
      });

      const report = await executeInspection(deps);
      // meta(1) + script(1) + stylesheet(1) + domMarkers(2) + htmlSnippets(1) = 6
      expect(report.coverage?.details?.domItemCount).toBe(6);
      expect(report.coverage?.overallStatus).toBe('complete');
    });
  });

  describe('v1.7.1 T11: KEV 名指し表示・AngularJS 1.5.8 推奨対応・CLR 2.0 Unknown 修正', () => {
    it('指摘 E: jQuery 3.1.1 の観測値と Markdown 表に CVE-2020-11023 が KEV として名指しされ、他の 2 件は KEV と書かれないこと', async () => {
      setTestAdvisoryDatabase(fixtureDb);
      const deps = createMockDeps({
        tab: { id: 101, url: 'https://jq-kev.example.test/' },
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            url: 'https://jq-kev.example.test/',
            metaTags: [],
            scriptUrls: ['https://jq-kev.example.test/js/jquery-3.1.1.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { jquery: '3.1.1' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://jq-kev.example.test/',
          headers: {},
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const jqueryTech = report.technologies.find((t) => t.technology === 'jQuery');
      expect(jqueryTech?.advisories).toHaveLength(3);

      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-JQUERY');
      expect(cveCheck).toBeDefined();
      expect(cveCheck?.observed).toContain('CISA KEV: CVE-2020-11023');
      // 他の 2 件 (CVE-2020-11022, CVE-2019-11358) は観測値で KEV として書かれないこと
      expect(cveCheck?.observed).not.toContain('CVE-2020-11022');
      expect(cveCheck?.observed).not.toContain('CVE-2019-11358');

      // Markdown セクション 6 の CISA KEV 列でも CVE-2020-11023 のみが KEV として名指しされること
      const md = generateMarkdownReport(report);
      const sec6 = md.split('## 6. EOL・既知脆弱性情報')[1]?.split('## 7.')[0] || '';
      expect(sec6).toContain('**CISA KEV: CVE-2020-11023**');
      expect(sec6).not.toContain('CISA KEV: CVE-2020-11022');
      expect(sec6).not.toContain('CISA KEV: CVE-2019-11358');
    });

    it('指摘 C: AngularJS 1.5.8 の調査レポートで推奨対応に解消できる件数と修正版なしの件数があり、合計が該当 CVE 数と一致すること', async () => {
      setTestAdvisoryDatabase(fixtureDb);
      const deps = createMockDeps({
        tab: { id: 101, url: 'https://ng1.example.test/' },
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            url: 'https://ng1.example.test/',
            metaTags: [],
            scriptUrls: ['https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js'],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: { angularjs: '1.5.8' },
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: 'https://ng1.example.test/',
          headers: {},
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
      });

      const report = await executeInspection(deps);
      const ngTech = report.technologies.find((t) => t.technology === 'AngularJS');
      expect(ngTech).toBeDefined();
      const totalCves = ngTech?.advisories?.length ?? 0;
      expect(totalCves).toBeGreaterThan(0);

      const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-ANGULARJS');
      expect(cveCheck).toBeDefined();
      const match = cveCheck?.recommendation.match(/(\d+)\s*件解消、残り\s*(\d+)\s*件は修正版なし/);
      expect(match).not.toBeNull();
      expect(Number(match![1]) + Number(match![2])).toBe(totalCves);
    });

    it('T08 の修正: testaspnet スナップショット (X-AspNet-Version: 2.0.50727) で ASP.NET が EOL にならず Unknown になり、詳細に 2.0・3.0 と 3.5 SP1 の期限が出て SEC-DISC-03 が LOW で出ること', async () => {
      setTestAdvisoryDatabase(fixtureDb);
      const snapPath = path.resolve(
        __dirname,
        'fixtures',
        'snapshots',
        'testaspnet.vulnweb.com.json'
      );
      const snap = JSON.parse(fs.readFileSync(snapPath, 'utf-8'));

      const deps = createMockDeps({
        tab: { id: 101, url: snap.finalUrl || snap.url },
        fetchDomSignals: vi.fn().mockResolvedValue(
          createMockDomSignals({
            url: snap.finalUrl || snap.url,
            metaTags: [],
            scriptUrls: [],
            linkUrls: [{ rel: 'stylesheet', href: 'http://testaspnet.vulnweb.com/styles.css' }],
          })
        ),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: {},
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: snap.finalUrl || snap.url,
          headers: snap.responseHeaders,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue(snap.cookies || []),
      });

      const report = await executeInspection(deps);
      const aspnet = report.technologies.find((t) => t.technology === 'ASP.NET');
      expect(aspnet).toBeDefined();
      expect(aspnet?.supportStatus).toBe('Unknown');
      expect(aspnet?.eolInfo?.status).toBe('Unknown');
      expect(aspnet?.eolInfo?.note).toContain('2011-07-12');
      expect(aspnet?.eolInfo?.note).toContain('2029-01-09');

      // EOL チェック (SEC-EOL-ASP.NET) が発生していないこと
      expect(report.securityChecks.find((c) => c.checkId === 'SEC-EOL-ASP.NET')).toBeUndefined();

      // SEC-DISC-03 は引き続き LOW で出ること
      const disc03 = report.securityChecks.find((c) => c.checkId === 'SEC-DISC-03');
      expect(disc03).toBeDefined();
      expect(disc03?.status).toBe('warning');
      expect(disc03?.severity).toBe('low');

      const md = generateMarkdownReport(report);
      expect(md).toContain('2011-07-12');
      expect(md).toContain('2029-01-09');
    });
  });
});
