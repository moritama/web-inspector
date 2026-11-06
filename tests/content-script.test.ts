// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * Content Script (DOMシグナル抽出) の単体テスト (tests/content-script.test.ts)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  executeInspection,
  InspectionDependencies,
} from '../src/background/service-worker';
import {
  CONTENT_SCRIPT_GUARD_KEY,
  extractDomSignals,
  initContentScript,
  isResourceLinkRel,
  resolveToAbsoluteUrl,
} from '../src/content/content-script';
import { generateMarkdownReport } from '../src/export/markdown';
import {
  analyzeExternalConnections,
  collectLoadedResourceUrls,
} from '../src/security/domain-analyzer';
import { checkHttpsAndMixedContent } from '../src/security/https';
import { InspectedCookieInfo } from '../src/shared/types';
// @ts-expect-error .mjs スクリプトをテストから直接インポート
import { lintReportPair } from '../scripts/report-lint.mjs';

describe('extractDomSignals (Content Script)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    document.head.innerHTML = '';
  });

  it('data-v-xxxxxxxx 属性を持つ要素から Vue のシグナル (data-v-) を検出できること', () => {
    document.body.innerHTML = `
      <div id="app">
        <div data-v-7ba5bd90 class="user-profile">
          <span data-v-7ba5bd90>Hello Vue</span>
        </div>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-v-');
  });

  it('data-astro-cid-xxxx 属性を持つ要素から Astro のシグナルを検出できること', () => {
    document.body.innerHTML = `
      <main data-astro-cid-j7pv25f6>
        <h1 data-astro-cid-j7pv25f6>Welcome to Astro</h1>
      </main>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-astro-cid-');
  });

  it('data-sveltekit-xxx 属性を持つ要素から SvelteKit のシグナルを検出できること', () => {
    document.body.innerHTML = `
      <div data-sveltekit-preload-data="hover">
        <a href="/about">About</a>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('data-sveltekit-');
  });

  it('noscript 内に配置された GTM の iframe (ns.html) を検出できること', () => {
    // JS有効時のブラウザ挙動と同様に、noscript タグ内にテキストとして iframe が格納されている場合
    const noscript = document.createElement('noscript');
    noscript.textContent = '<iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX" height="0" width="0" style="display:none;visibility:hidden"></iframe>';
    document.body.appendChild(noscript);

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('googletagmanager.com/ns.html');
  });

  it('AngularJS の [ng-app] 属性要素が存在する場合に domMarkers に検出されること', () => {
    document.body.innerHTML = `
      <div ng-app="myApp" ng-controller="MainCtrl">
        <p>AngularJS content</p>
      </div>
    `;

    const signals = extractDomSignals();
    expect(signals.domMarkers).toContain('[ng-app]');
    expect(signals.domMarkers).toContain('[ng-controller]');
  });

  it('T07 (SPEC-15): <img srcset="http://...">, <form action="http://...">, <video src="http://..."> 等が混在コンテンツとして検出され、form は high、img / video は low と判定されること', () => {
    if ((window as any).happyDOM?.setURL) {
      (window as any).happyDOM.setURL('https://example.com/');
    } else {
      window.location.href = 'https://example.com/';
    }

    document.body.innerHTML = `
      <img srcset="http://cdn.example.com/img-1x.jpg 1x, https://cdn.example.com/img-2x.jpg 2x">
      <form action="http://insecure.example.com/submit" method="post"></form>
      <video src="http://media.example.com/movie.mp4"></video>
      <audio src="http://media.example.com/voice.mp3"></audio>
      <video><source src="http://media.example.com/sub.webm"></video>
      <picture><source srcset="http://cdn.example.com/pic.webp 1x"></picture>
      <object data="http://legacy.example.com/flash.swf"></object>
      <embed src="http://legacy.example.com/embed.swf">
    `;

    const signals = extractDomSignals();
    expect(signals.mixedContent).toEqual(
      expect.arrayContaining([
        { resourceType: 'image', url: 'http://cdn.example.com/img-1x.jpg' },
        { resourceType: 'form', url: 'http://insecure.example.com/submit' },
        { resourceType: 'video', url: 'http://media.example.com/movie.mp4' },
        { resourceType: 'audio', url: 'http://media.example.com/voice.mp3' },
        { resourceType: 'video', url: 'http://media.example.com/sub.webm' },
        { resourceType: 'image', url: 'http://cdn.example.com/pic.webp' },
        { resourceType: 'object', url: 'http://legacy.example.com/flash.swf' },
        { resourceType: 'embed', url: 'http://legacy.example.com/embed.swf' },
      ])
    );

    // form 単独での評価: high
    const formItems = signals.mixedContent.filter((i) => i.resourceType === 'form');
    expect(formItems).toHaveLength(1);
    const formChecks = checkHttpsAndMixedContent('https://example.com/', true, formItems);
    const activeCheck = formChecks.find((c) => c.checkId === 'SEC-MIXED-ACTIVE');
    expect(activeCheck?.severity).toBe('high');
    expect(activeCheck?.status).toBe('fail');

    // img / video (パッシブ混在) での評価: low
    const passiveItems = signals.mixedContent.filter(
      (i) => i.resourceType === 'image' || i.resourceType === 'video'
    );
    expect(passiveItems.length).toBeGreaterThanOrEqual(2);
    const passiveChecks = checkHttpsAndMixedContent('https://example.com/', true, passiveItems);
    const passiveCheck = passiveChecks.find((c) => c.checkId === 'SEC-MIXED-PASSIVE');
    expect(passiveCheck?.severity).toBe('low');
    expect(passiveCheck?.status).toBe('warning');
  });

  it('T09 (DOC-06): <link rel="stylesheet"> の URL から Bootstrap バージョンを抽出し、死んでいた CSS コメント抽出には依存しないこと', () => {
    const origConsoleError = console.error;
    console.error = (...args: unknown[]) => {
      const msg = String(args[0] ?? '');
      if (msg.includes('CSS file loading is disabled')) return;
      origConsoleError(...args);
    };
    try {
      document.head.innerHTML = `
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
      `;

      const signals = extractDomSignals();
      expect(signals.cssAssets).toBeDefined();
      expect(signals.cssAssets).toEqual([
        {
          href: 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css',
          filename: 'bootstrap.min.css',
          inferredLibrary: 'Bootstrap',
          inferredVersion: '5.3.2',
          evidenceType: 'css-url',
          confidence: 'medium',
        },
      ]);
    } finally {
      console.error = origConsoleError;
    }
  });

  it('T11 (IMPL-08): 先頭の実行済みフラグにより二重注入を防ぎ、メッセージリスナーが1回だけ登録されること', () => {
    const globalScope = globalThis as Record<string, unknown>;
    const prevFlag = globalScope[CONTENT_SCRIPT_GUARD_KEY];
    const prevChrome = globalScope.chrome;

    const addListenerMock = vi.fn();
    globalScope.chrome = {
      runtime: {
        onMessage: {
          addListener: addListenerMock,
        },
      },
    };
    delete globalScope[CONTENT_SCRIPT_GUARD_KEY];

    try {
      // 1回目の注入: フラグが立ち、リスナーが1回登録される
      const firstResult = initContentScript();
      expect(firstResult).toBe(true);
      expect(globalScope[CONTENT_SCRIPT_GUARD_KEY]).toBe(true);
      expect(addListenerMock).toHaveBeenCalledTimes(1);

      // 2回目の注入: 先頭の実行済みフラグによりスキップされ、リスナーは二重登録されない
      const secondResult = initContentScript();
      expect(secondResult).toBe(false);
      expect(addListenerMock).toHaveBeenCalledTimes(1);

      // 登録されたリスナーが EXTRACT_DOM_SIGNALS に対して応答を返すことを確認
      const listener = addListenerMock.mock.calls[0][0];
      const sendResponse = vi.fn();
      const handled = listener({ type: 'EXTRACT_DOM_SIGNALS' }, {}, sendResponse);
      expect(handled).toBe(true);
      expect(sendResponse).toHaveBeenCalledTimes(1);
    } finally {
      globalScope[CONTENT_SCRIPT_GUARD_KEY] = prevFlag;
      globalScope.chrome = prevChrome;
    }
  });

  describe('v1.7.1 T05: 相対 URL 解決・Resource Timing 収集・非通信 link/form の分離', () => {
    it('相対 URL の script[src] と link[rel="stylesheet"] が baseURI 基準の絶対 URL に解決され、元の属性値も rawScriptUrls / rawLinkUrls に保持されること', () => {
      const origConsoleError = console.error;
      console.error = (...args: unknown[]) => {
        const msg = String(args[0] ?? '');
        if (msg.includes('CSS file loading is disabled')) return;
        origConsoleError(...args);
      };
      try {
        document.head.innerHTML = `
          <link rel="stylesheet" href="/assets/css/bootstrap-5.3.3.min.css">
        `;
        document.body.innerHTML = `
          <script src="/assets/js/jquery-3.7.1.min.js"></script>
        `;

        const baseUrl = 'https://relative.example.test/sub/page.html';
        const signals = extractDomSignals(baseUrl);

        expect(signals.scriptUrls).toEqual([
          'https://relative.example.test/assets/js/jquery-3.7.1.min.js',
        ]);
        expect(signals.rawScriptUrls).toEqual(['/assets/js/jquery-3.7.1.min.js']);
        expect(signals.linkUrls).toEqual([
          {
            rel: 'stylesheet',
            href: 'https://relative.example.test/assets/css/bootstrap-5.3.3.min.css',
          },
        ]);
        expect(signals.rawLinkUrls).toEqual([
          {
            rel: 'stylesheet',
            href: '/assets/css/bootstrap-5.3.3.min.css',
          },
        ]);
        expect(signals.cssAssets?.[0]?.href).toBe(
          'https://relative.example.test/assets/css/bootstrap-5.3.3.min.css'
        );

        // 相対 URL のみのページで自ホストが通信先に載り、件数が読み込み数（ページ本体 + CSS + JS = 3）と一致すること
        const resourceUrls = collectLoadedResourceUrls(baseUrl, signals);
        const analysis = analyzeExternalConnections(baseUrl, resourceUrls);
        expect(analysis.totalConnections).toBe(1);
        expect(analysis.connections[0].hostname).toBe('relative.example.test');
        expect(analysis.connections[0].resourceCount).toBe(3);
      } finally {
        console.error = origConsoleError;
      }
    });

    it('50 本の hreflang alternate リンク・canonical・dns-prefetch・preconnect・form[action] が linkUrls や externalConnections に一切入らず referenceOnlyUrls に保持されること', () => {
      const origConsoleError = console.error;
      console.error = (...args: unknown[]) => {
        const msg = String(args[0] ?? '');
        if (msg.includes('CSS file loading is disabled')) return;
        origConsoleError(...args);
      };
      try {
        const alternateLinks = Array.from({ length: 50 }, (_, i) => {
          const lang = `lang${i + 1}`;
          return `<link rel="alternate" hreflang="${lang}" href="https://${lang}.i18n.example.test/page">`;
        }).join('\n');

        document.head.innerHTML = `
          <link rel="stylesheet" href="/css/main.css">
          <link rel="icon" href="/favicon.ico">
          <link rel="preload" href="/fonts/main.woff2" as="font">
          <link rel="modulepreload" href="/js/module.js">
          <link rel="manifest" href="/site.webmanifest">
          <link rel="canonical" href="https://canonical.example.test/page">
          <link rel="prev" href="https://prev.example.test/page">
          <link rel="next" href="https://next.example.test/page">
          <link rel="dns-prefetch" href="https://dns-prefetch.example.test">
          <link rel="preconnect" href="https://preconnect.example.test">
          ${alternateLinks}
        `;
        document.body.innerHTML = `
          <form action="https://form-action.example.test/submit" method="post">
            <input type="text" name="q">
          </form>
        `;

        const baseUrl = 'https://main.example.test/articles/1';
        const signals = extractDomSignals(baseUrl);

        // stylesheet, icon, preload, modulepreload, manifest の 5 件のみが linkUrls に入ること
        expect(signals.linkUrls).toEqual([
          { rel: 'stylesheet', href: 'https://main.example.test/css/main.css' },
          { rel: 'icon', href: 'https://main.example.test/favicon.ico' },
          { rel: 'preload', href: 'https://main.example.test/fonts/main.woff2' },
          { rel: 'modulepreload', href: 'https://main.example.test/js/module.js' },
          { rel: 'manifest', href: 'https://main.example.test/site.webmanifest' },
        ]);

        // 50 本の alternate + canonical + prev + next + dns-prefetch + preconnect + form[action] = 56 件が referenceOnlyUrls に入ること
        expect(signals.referenceOnlyUrls?.length).toBe(56);

        const resourceUrls = collectLoadedResourceUrls(baseUrl, signals);
        const analysis = analyzeExternalConnections(baseUrl, resourceUrls);

        expect(analysis.connections.map((c) => c.hostname)).toEqual(['main.example.test']);
        expect(analysis.thirdPartyCount).toBe(0);
      } finally {
        console.error = origConsoleError;
      }
    });

    it('JS の fetch（performance.getEntriesByType("resource")）と <img> で別ホストにアクセスしたとき、両方とも通信先に載ること', () => {
      const getEntriesSpy = vi
        .spyOn(performance, 'getEntriesByType')
        .mockImplementation((type: string) => {
          if (type === 'resource') {
            return [
              {
                name: 'https://api-fetch.example.test/v1/profile?secret=123',
                initiatorType: 'fetch',
              } as unknown as PerformanceEntry,
              {
                name: 'https://xhr.example.test/v1/events#frag',
                initiatorType: 'xmlhttprequest',
              } as unknown as PerformanceEntry,
            ];
          }
          return [];
        });

      try {
        document.body.innerHTML = `
          <img src="https://img-cdn.example.test/hero.webp?ver=2" alt="hero">
        `;

        const baseUrl = 'https://app.example.test/';
        const signals = extractDomSignals(baseUrl);

        expect(signals.resourceEntries).toEqual([
          {
            url: 'https://api-fetch.example.test/v1/profile?secret=123',
            initiatorType: 'fetch',
          },
          {
            url: 'https://xhr.example.test/v1/events#frag',
            initiatorType: 'xmlhttprequest',
          },
        ]);
        expect(signals.domResourceUrls).toContain('https://img-cdn.example.test/hero.webp?ver=2');

        const resourceUrls = collectLoadedResourceUrls(baseUrl, signals);
        const analysis = analyzeExternalConnections(baseUrl, resourceUrls);
        const hostnames = analysis.connections.map((c) => c.hostname);

        expect(hostnames).toContain('app.example.test');
        expect(hostnames).toContain('api-fetch.example.test');
        expect(hostnames).toContain('xhr.example.test');
        expect(hostnames).toContain('img-cdn.example.test');

        // サンプル URL のクエリとフラグメントがマスクされていること
        const fetchConn = analysis.connections.find(
          (c) => c.hostname === 'api-fetch.example.test'
        );
        expect(fetchConn?.sampleUrls).toEqual(['https://api-fetch.example.test/v1/profile']);
      } finally {
        getEntriesSpy.mockRestore();
      }
    });

    it('isResourceLinkRel と resolveToAbsoluteUrl が各種入力を正しく判定・解決すること', () => {
      expect(isResourceLinkRel('stylesheet')).toBe(true);
      expect(isResourceLinkRel('preload stylesheet')).toBe(true);
      expect(isResourceLinkRel('shortcut icon')).toBe(true);
      expect(isResourceLinkRel('apple-touch-icon')).toBe(true);
      expect(isResourceLinkRel('modulepreload')).toBe(true);
      expect(isResourceLinkRel('manifest')).toBe(true);

      expect(isResourceLinkRel('alternate')).toBe(false);
      expect(isResourceLinkRel('canonical')).toBe(false);
      expect(isResourceLinkRel('dns-prefetch')).toBe(false);
      expect(isResourceLinkRel('preconnect')).toBe(false);
      expect(isResourceLinkRel('https://api.w.org/')).toBe(false);

      expect(resolveToAbsoluteUrl('/js/app.js', 'https://app.example.test/dir/index.html')).toBe(
        'https://app.example.test/js/app.js'
      );
      expect(resolveToAbsoluteUrl('javascript:void(0)', 'https://app.example.test/')).toBeNull();
      expect(resolveToAbsoluteUrl('data:image/png;base64,AAA', 'https://app.example.test/')).toBeNull();
    });

    it('T04 の公開サイトスナップショット（testasp.vulnweb.com、testaspnet.vulnweb.com、demo.testfire.net、http.badssl.com、www.drupal.org ほか）で通信先が 0 件にならず、R04・R08 をパスすること', async () => {
      const origConsoleError = console.error;
      console.error = (...args: unknown[]) => {
        const msg = String(args[0] ?? '');
        if (msg.includes('CSS file loading is disabled')) return;
        origConsoleError(...args);
      };

      try {
        const snapshotsDir = path.resolve(__dirname, 'fixtures', 'snapshots');
        const targetHosts = [
          'testasp.vulnweb.com',
          'testaspnet.vulnweb.com',
          'demo.testfire.net',
          'http.badssl.com',
          'www.drupal.org',
          'mixed-form.badssl.com',
        ];

        for (const host of targetHosts) {
          const jsonPath = path.join(snapshotsDir, `${host}.json`);
          expect(fs.existsSync(jsonPath)).toBe(true);

          const snap = JSON.parse(fs.readFileSync(jsonPath, 'utf-8')) as {
            url: string;
            finalUrl?: string;
            responseHeaders?: Record<string, string[]>;
            resourceTiming?: Array<{ name: string; initiatorType?: string }>;
            cookies?: InspectedCookieInfo[];
            html?: string;
          };

          const pageUrl = snap.finalUrl || snap.url;
          const html =
            snap.html || fs.readFileSync(path.join(snapshotsDir, `${host}.html`), 'utf-8');

          document.documentElement.innerHTML = html;

          const getEntriesSpy = vi
            .spyOn(performance, 'getEntriesByType')
            .mockImplementation((type: string) => {
              if (type === 'resource') {
                return (snap.resourceTiming || []) as unknown as PerformanceEntry[];
              }
              return [];
            });

          try {
            const signals = extractDomSignals(pageUrl);
            const deps: InspectionDependencies = {
              tab: { id: 1, url: pageUrl },
              fetchDomSignals: async () => signals,
              fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
              getCachedHeaders: async () => ({
                url: pageUrl,
                headers: snap.responseHeaders || {},
                observed: true,
              }),
              getInspectedCookies: async () => snap.cookies || [],
              getAllFindingExceptions: async () => [],
              saveReport: async () => {},
              hasWebRequestPermission: true,
            };

            const report = await executeInspection(deps);

            // 通信先が 0 件にならないこと
            expect(report.externalConnections?.totalConnections).toBeGreaterThanOrEqual(1);
            const connHosts =
              report.externalConnections?.connections.map((c) => c.hostname) || [];
            const selfHostname = new URL(pageUrl).hostname.toLowerCase();
            expect(connHosts).toContain(selfHostname);

            // mixed-form.badssl.com では form[action] の送信先 (http.badssl.com) が通信先に入らないこと
            if (host === 'mixed-form.badssl.com') {
              expect(connHosts).not.toContain('http.badssl.com');
            }

            // www.drupal.org では sampleUrls の ?token=... 等がマスクされていること
            if (host === 'www.drupal.org') {
              for (const c of report.externalConnections?.connections || []) {
                for (const sUrl of c.sampleUrls) {
                  expect(sUrl).not.toContain('?');
                  expect(sUrl).not.toContain('#');
                }
              }
            }

            // 整合性チェッカーの R04 と R08 が保留でなく合格すること
            const md = generateMarkdownReport(report);
            const lintRes = lintReportPair(report, md);
            expect(lintRes.pendingChecks).toBe(0);
            const r04 = lintRes.results.find((r: { id: string }) => r.id === 'R04');
            const r08 = lintRes.results.find((r: { id: string }) => r.id === 'R08');
            expect(r04?.passed).toBe(true);
            expect(r08?.passed).toBe(true);
          } finally {
            getEntriesSpy.mockRestore();
          }
        }
      } finally {
        console.error = origConsoleError;
      }
    });
  });

  describe('v1.7.1 T06: 混在コンテンツ URL (badssl 3 サイト)・N2 DOM 検出・Content Script 途中失敗', () => {
    it('badssl 3 サイトのスナップショット (mixed / mixed-script / mixed-form) で混在コンテンツの観測値に要素と URL が出ること', async () => {
      const origConsoleError = console.error;
      console.error = (...args: unknown[]) => {
        const msg = String(args[0] ?? '');
        if (msg.includes('CSS file loading is disabled')) return;
        origConsoleError(...args);
      };

      try {
        const snapshotsDir = path.resolve(__dirname, 'fixtures', 'snapshots');
        const expectations: Array<{
          host: string;
          checkId: string;
          expectedObservedFragment: string;
        }> = [
          {
            host: 'mixed.badssl.com',
            checkId: 'SEC-MIXED-PASSIVE',
            expectedObservedFragment: 'img: http://mixed.badssl.com/image.jpg',
          },
          {
            host: 'mixed-script.badssl.com',
            checkId: 'SEC-MIXED-ACTIVE',
            expectedObservedFragment: 'script: http://mixed-script.badssl.com/nonsecure.js',
          },
          {
            host: 'mixed-form.badssl.com',
            checkId: 'SEC-MIXED-ACTIVE',
            expectedObservedFragment:
              'form[action]: http://http.badssl.com/resources/form-submitted.html',
          },
        ];

        for (const { host, checkId, expectedObservedFragment } of expectations) {
          const snap = JSON.parse(
            fs.readFileSync(path.join(snapshotsDir, `${host}.json`), 'utf-8')
          ) as {
            url: string;
            finalUrl?: string;
            responseHeaders?: Record<string, string[]>;
            resourceTiming?: Array<{ name: string; initiatorType?: string }>;
            cookies?: InspectedCookieInfo[];
            html?: string;
          };
          const pageUrl = snap.finalUrl || snap.url;
          const html =
            snap.html || fs.readFileSync(path.join(snapshotsDir, `${host}.html`), 'utf-8');

          document.documentElement.innerHTML = html;
          const signals = extractDomSignals(pageUrl);
          const report = await executeInspection({
            tab: { id: 1, url: pageUrl },
            fetchDomSignals: async () => signals,
            fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
            getCachedHeaders: async () => ({
              url: pageUrl,
              headers: snap.responseHeaders || {},
              observed: true,
            }),
            getInspectedCookies: async () => snap.cookies || [],
            getAllFindingExceptions: async () => [],
            saveReport: async () => {},
            hasWebRequestPermission: true,
          });

          const check = report.securityChecks.find((c) => c.checkId === checkId);
          expect(check).toBeDefined();
          expect(check?.observed).toContain(expectedObservedFragment);
        }
      } finally {
        console.error = origConsoleError;
      }
    });

    it('angular.dev スナップショットでビルドメタデータ付き ng-version="22.2.5+sha-d881689" および _nghost- / _ngcontent- / [ng-server-context] から Angular 22.2.5 が検出されること', async () => {
      const origConsoleError = console.error;
      console.error = (...args: unknown[]) => {
        const msg = String(args[0] ?? '');
        if (msg.includes('CSS file loading is disabled')) return;
        origConsoleError(...args);
      };

      try {
        const snapshotsDir = path.resolve(__dirname, 'fixtures', 'snapshots');
        const snap = JSON.parse(
          fs.readFileSync(path.join(snapshotsDir, 'angular.dev.json'), 'utf-8')
        ) as {
          url: string;
          finalUrl?: string;
          responseHeaders?: Record<string, string[]>;
          resourceTiming?: Array<{ name: string; initiatorType?: string }>;
          cookies?: InspectedCookieInfo[];
          html?: string;
        };
        const pageUrl = snap.finalUrl || snap.url;
        const html =
          snap.html || fs.readFileSync(path.join(snapshotsDir, 'angular.dev.html'), 'utf-8');

        document.documentElement.innerHTML = html;
        const signals = extractDomSignals(pageUrl);
        expect(signals.domMarkers).toContain('ng-version="22.2.5+sha-d881689"');
        expect(signals.domMarkers).toContain('_nghost-');
        expect(signals.domMarkers).toContain('_ngcontent-');
        expect(signals.domMarkers).toContain('[ng-server-context]');

        const report = await executeInspection({
          tab: { id: 1, url: pageUrl },
          fetchDomSignals: async () => signals,
          fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
          getCachedHeaders: async () => ({
            url: pageUrl,
            headers: snap.responseHeaders || {},
            observed: true,
          }),
          getInspectedCookies: async () => snap.cookies || [],
          getAllFindingExceptions: async () => [],
          saveReport: async () => {},
          hasWebRequestPermission: true,
        });

        const angular = report.technologies.find((t) => t.technology === 'Angular');
        expect(angular).toBeDefined();
        expect(angular?.version).toBe('22.2.5');
        expect(angular?.confidence).toBe(95);
      } finally {
        console.error = origConsoleError;
      }
    });

    it('angularjs.org (Firebase 404 ページ) と www.drupal.org (Fastly Client Challenge ページ) のスナップショットには対象技術の印が無く誤検出しないこと、また代替シグナルがある DOM では AngularJS と Drupal が検出されること', async () => {
      const snapshotsDir = path.resolve(__dirname, 'fixtures', 'snapshots');

      // 1. angularjs.org スナップショット: Firebase Hosting の 404 Site Not Found ページ
      const angularjsHtml = fs.readFileSync(
        path.join(snapshotsDir, 'angularjs.org.html'),
        'utf-8'
      );
      expect(angularjsHtml).toContain('<title>Site Not Found</title>');
      expect(angularjsHtml).not.toMatch(/ng-app|angular/i);
      document.documentElement.innerHTML = angularjsHtml;
      const angularjsSnapSignals = extractDomSignals('https://angularjs.org/');
      const angularjsSnapReport = await executeInspection({
        tab: { id: 1, url: 'https://angularjs.org/' },
        fetchDomSignals: async () => angularjsSnapSignals,
        fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
        getCachedHeaders: async () => ({
          url: 'https://angularjs.org/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: async () => [],
        getAllFindingExceptions: async () => [],
        saveReport: async () => {},
        hasWebRequestPermission: true,
      });
      expect(
        angularjsSnapReport.technologies.find((t) => t.technology === 'AngularJS')
      ).toBeUndefined();

      // 2. www.drupal.org スナップショット: Fastly の Client Challenge CAPTCHA ページ
      const drupalHtml = fs.readFileSync(
        path.join(snapshotsDir, 'www.drupal.org.html'),
        'utf-8'
      );
      expect(drupalHtml).toContain('<title>Client Challenge</title>');
      expect(drupalHtml).toContain('fastlyLogo');
      expect(drupalHtml).not.toMatch(/drupal/i);
      document.documentElement.innerHTML = drupalHtml;
      const drupalSnapSignals = extractDomSignals('https://www.drupal.org/');
      const drupalSnapReport = await executeInspection({
        tab: { id: 1, url: 'https://www.drupal.org/' },
        fetchDomSignals: async () => drupalSnapSignals,
        fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
        getCachedHeaders: async () => ({
          url: 'https://www.drupal.org/',
          headers: {},
          observed: true,
        }),
        getInspectedCookies: async () => [],
        getAllFindingExceptions: async () => [],
        saveReport: async () => {},
        hasWebRequestPermission: true,
      });
      expect(
        drupalSnapReport.technologies.find((t) => t.technology === 'Drupal')
      ).toBeUndefined();

      // 3. AngularJS の代替シグナル (data-ng-app / .ng-scope) を持つ DOM では AngularJS が検出されること
      document.documentElement.innerHTML = `
        <html><body>
          <div data-ng-app="portalApp" class="ng-scope">
            <span class="ng-binding">Hello</span>
          </div>
        </body></html>
      `;
      const altAngularJsSignals = extractDomSignals('https://legacy.example.test/');
      expect(altAngularJsSignals.domMarkers).toContain('[data-ng-app]');
      expect(altAngularJsSignals.domMarkers).toContain('.ng-scope');

      // 4. Drupal の代替シグナル (data-drupal-selector / drupal-settings-json) を持つ DOM では Drupal が検出されること
      document.documentElement.innerHTML = `
        <html><head>
          <script type="application/json" data-drupal-selector="drupal-settings-json">{"path":{"baseUrl":"/"}}</script>
        </head><body>
          <div data-drupal-messages-fallback class="hidden"></div>
        </body></html>
      `;
      const altDrupalSignals = extractDomSignals('https://cms.example.test/');
      expect(altDrupalSignals.domMarkers).toContain('data-drupal-');
      expect(altDrupalSignals.domMarkers).toContain('[data-drupal-selector]');
    });

    it('extractDomSignals の途中で例外が発生したとき、collectionPartial: true が記録され完全性が「部分的 (partial)」になること', async () => {
      document.body.innerHTML = `
        <div ng-version="19.1.0">App</div>
      `;

      const origQuerySelectorAll = document.querySelectorAll.bind(document);
      const qsaSpy = vi
        .spyOn(document, 'querySelectorAll')
        .mockImplementation(((selector: string) => {
          if (selector === 'script[src]') {
            throw new Error('Simulated DOM querySelectorAll failure');
          }
          return origQuerySelectorAll(selector);
        }) as typeof document.querySelectorAll);

      try {
        const signals = extractDomSignals('https://partial.example.test/');
        expect(signals.collectionPartial).toBe(true);
        expect(
          signals.collectionErrors?.some((e) =>
            e.includes('Simulated DOM querySelectorAll failure')
          )
        ).toBe(true);
        // 他のステップ（DOM セレクタ探査）は継続して収集できていること
        expect(signals.domMarkers).toContain('ng-version="19.1.0"');

        const report = await executeInspection({
          tab: { id: 1, url: 'https://partial.example.test/' },
          fetchDomSignals: async () => signals,
          fetchRuntimeVersions: async () => ({ versions: {}, frameworkMarkers: [] }),
          getCachedHeaders: async () => ({
            url: 'https://partial.example.test/',
            headers: { 'x-content-type-options': ['nosniff'] },
            observed: true,
          }),
          getInspectedCookies: async () => [],
          getAllFindingExceptions: async () => [],
          saveReport: async () => {},
          hasWebRequestPermission: true,
        });

        expect(report.coverage?.overallStatus).toBe('partial');
        expect(report.coverage?.dom).toBe('partial');
        expect(
          report.coverage?.details?.partialReasons?.some((r) =>
            r.includes('Simulated DOM querySelectorAll failure')
          )
        ).toBe(true);
      } finally {
        qsaSpy.mockRestore();
      }
    });
  });
});
