/**
 * Web Technology & Security Inspector
 * Content Script (src/content/content-script.ts) - Version 1.1.0
 * 閲覧中のWebページ内でDOM、CSSアセット、混在コンテンツを収集します
 */

import {
  DomSignals,
  InspectedCssAsset,
  MixedContentItem,
  ObservedResourceEntry,
  ReferenceOnlyUrlItem,
} from '../shared/types';
import { DOM_MARKER_SELECTORS } from './dom-selectors.generated';

/**
 * 二重注入を防ぐための実行済みフラグ名 (v1.7.0 T11 / IMPL-08)
 */
export const CONTENT_SCRIPT_GUARD_KEY = '__WEB_INSPECTOR_CONTENT_SCRIPT_INJECTED__';

/**
 * DOM の <link> 要素のうち、実際にリソースを読み込む対象として扱う rel トークン一覧 (v1.7.1 T05)
 */
export const ALLOWED_RESOURCE_LINK_REL_TOKENS: ReadonlySet<string> = new Set([
  'stylesheet',
  'preload',
  'modulepreload',
  'icon',
  'apple-touch-icon',
  'apple-touch-icon-precomposed',
  'mask-icon',
  'manifest',
]);

/**
 * 通信を伴わない参照（またはヒントのみ）として通信先から除外する rel トークン一覧 (v1.7.1 T05)
 */
export const NON_CONNECTION_LINK_REL_TOKENS: ReadonlySet<string> = new Set([
  'alternate',
  'canonical',
  'prev',
  'next',
  'dns-prefetch',
  'preconnect',
  'shortlink',
  'pingback',
  'edituri',
  'wlwmanifest',
]);

/**
 * <link> の rel 属性値が、実際にリソースを読み込む対象（stylesheet, preload, modulepreload, icon, manifest）かどうかを判定する (v1.7.1 T05)
 */
export function isResourceLinkRel(rel: string | undefined | null): boolean {
  if (!rel) return false;
  const tokens = rel.toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return false;
  if (tokens.some((t) => NON_CONNECTION_LINK_REL_TOKENS.has(t))) {
    return false;
  }
  return tokens.some((t) => ALLOWED_RESOURCE_LINK_REL_TOKENS.has(t));
}

/**
 * ドキュメントの基準URL（document.baseURI / <base href> / window.location.href）を解決する (v1.7.1 T05)
 */
export function resolveDocumentBaseUri(baseUrlOverride?: string): string | undefined {
  const candidates = [
    baseUrlOverride,
    typeof document !== 'undefined' ? document.baseURI : undefined,
    typeof window !== 'undefined' ? window.location?.href : undefined,
  ];

  let fallbackBase: string | undefined;
  for (const candidate of candidates) {
    if (candidate && /^https?:\/\//i.test(candidate)) {
      fallbackBase = candidate;
      break;
    }
  }

  if (typeof document !== 'undefined') {
    const baseEl = document.querySelector('base[href]');
    const baseHref = baseEl?.getAttribute('href')?.trim();
    if (baseHref) {
      try {
        const resolvedBase = fallbackBase ? new URL(baseHref, fallbackBase) : new URL(baseHref);
        if (resolvedBase.protocol === 'http:' || resolvedBase.protocol === 'https:') {
          return resolvedBase.href;
        }
      } catch {
        // 無効な <base href> はフォールバックを使用
      }
    }
  }

  return fallbackBase;
}

/**
 * 相対URLまたはプロトコル相対URLを document.baseURI 基準の絶対 http(s) URL に解決する (v1.7.1 T05)
 * data:, blob:, javascript:, mailto:, tel:, about: などの非ネットワークスキームは null を返す。
 */
export function resolveToAbsoluteUrl(
  rawUrl: string | undefined | null,
  baseUri?: string
): string | null {
  const trimmed = (rawUrl || '').trim();
  if (!trimmed) return null;
  if (/^(?:javascript|data|blob|mailto|tel|about):/i.test(trimmed)) {
    return null;
  }

  const effectiveBase = baseUri || resolveDocumentBaseUri();
  if (effectiveBase && /^https?:\/\//i.test(effectiveBase)) {
    try {
      const resolved = new URL(trimmed, effectiveBase);
      if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
        return resolved.href;
      }
    } catch {
      // 単体解析へフォールバック
    }
  }

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const resolved = new URL(trimmed);
      if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
        return resolved.href;
      }
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Content Script のメッセージリスナーを初期化する。
 * 二重注入を防ぐため、先頭で実行済みの印を確かめ、既に初期化済みの場合は二重登録せず false を返す (IMPL-08)。
 */
export function initContentScript(): boolean {
  const globalScope = globalThis as Record<string, unknown>;
  if (globalScope[CONTENT_SCRIPT_GUARD_KEY] === true) {
    return false;
  }
  globalScope[CONTENT_SCRIPT_GUARD_KEY] = true;

  if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message && message.type === 'EXTRACT_DOM_SIGNALS') {
        const signals = extractDomSignals();
        sendResponse(signals);
        return true;
      }
      return false;
    });
  }
  return true;
}

// オンデマンド注入時、先頭で実行済みの印を確かめてメッセージリスナーを登録する (IMPL-08)
initContentScript();

/**
 * CSSファイル参照（linkタグ）を解析し、ライブラリ名とバージョンを推定する (ADD-02 / v1.7.1 T05)
 */
function inspectCssAssets(baseUri?: string): InspectedCssAsset[] {
  const assets: InspectedCssAsset[] = [];
  const linkElements = document.querySelectorAll<HTMLLinkElement>('link[href]');

  linkElements.forEach((link) => {
    const rel = link.getAttribute('rel') || '';
    const relTokens = rel.toLowerCase().trim().split(/\s+/).filter(Boolean);
    if (!isResourceLinkRel(rel) || !relTokens.includes('stylesheet')) return;

    const rawHref = link.getAttribute('href') || link.href;
    if (!rawHref) return;
    const href = resolveToAbsoluteUrl(rawHref, baseUri) || link.href || rawHref;

    let filename = '';
    try {
      const urlObj = new URL(href, baseUri || window.location.href);
      const segments = urlObj.pathname.split('/');
      filename = segments[segments.length - 1] || '';
    } catch {
      filename = href;
    }

    // 1. URLパス・ファイル名からのバージョン抽出
    // 例: /lib/bootstrap-4.3.1/css/bootstrap.min.css -> Bootstrap 4.3.1
    // 例: bootstrap.min.css?v=5.2.0 -> Bootstrap 5.2.0
    // 例: font-awesome/4.7.0/css/... -> FontAwesome 4.7.0
    const patterns = [
      {
        lib: 'Bootstrap',
        regex: /(?:bootstrap(?:-theme)?)[.-]([0-9.]+)(?:\.min)?\.css/i,
      },
      {
        lib: 'Bootstrap',
        regex: /\/bootstrap[/@-]([0-9.]+)\//i,
      },
      {
        lib: 'jQuery UI',
        regex: /jquery-ui[.-]([0-9.]+)(?:\.min)?\.css/i,
      },
      {
        lib: 'Tailwind CSS',
        regex: /tailwind(?:css)?[.-]([0-9.]+)(?:\.min)?\.css/i,
      },
      {
        lib: 'Font Awesome',
        regex: /(?:font-awesome|fontawesome)[.-]([0-9.]+)/i,
      },
    ];

    let detectedLib: string | undefined;
    let detectedVersion: string | null = null;
    const evidenceType: 'css-url' = 'css-url';
    const confidence: 'high' | 'medium' | 'low' = 'medium';

    for (const p of patterns) {
      const match = href.match(p.regex);
      if (match && match[1]) {
        detectedLib = p.lib;
        detectedVersion = match[1];
        break;
      }
    }

    // クエリパラメータ (?v=x.x.x) の確認
    if (!detectedVersion && detectedLib) {
      const qMatch = href.match(/[?&](?:v|version)=([0-9.]+)/i);
      if (qMatch && qMatch[1]) {
        detectedVersion = qMatch[1];
      }
    }

    // ※ブラウザのCSSOM仕様上、sheet.cssRules にはCSSコメントが保持されず、
    // 受動的調査（追加リクエストなし）では外部CSS内のコメントを読み取れないため、
    // URLパス・ファイル名・クエリパラメータからのみバージョンを抽出する (DOC-06)。

    if (detectedLib || /bootstrap|tailwind|bulma/i.test(href)) {
      assets.push({
        href,
        filename,
        inferredLibrary: detectedLib || (href.toLowerCase().includes('bootstrap') ? 'Bootstrap' : undefined),
        inferredVersion: detectedVersion,
        evidenceType,
        confidence,
      });
    }
  });

  return assets;
}

/**
 * ページ内のDOM、スクリプト、メタ情報、混在コンテンツ、読み込み済みリソースを安全に抽出する (v1.7.1 T05 / T06)
 */
export function extractDomSignals(baseUrlOverride?: string): DomSignals {
  const collectionErrors: string[] = [];
  const runStep = (stepLabel: string, fn: () => void): void => {
    try {
      fn();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      collectionErrors.push(
        `Content Script の DOM 収集 (${stepLabel}) が途中で失敗しました${msg ? `: ${msg}` : ''}`
      );
    }
  };

  let baseUri: string | undefined;
  runStep('baseUri', () => {
    baseUri = resolveDocumentBaseUri(baseUrlOverride);
  });

  const pageUrl =
    baseUrlOverride ||
    (typeof window !== 'undefined' && /^https?:\/\//i.test(window.location?.href || '')
      ? window.location.href
      : baseUri || (typeof window !== 'undefined' ? window.location?.href || '' : ''));
  const isPageHttps = /^https:/i.test(pageUrl) || window.location?.protocol === 'https:';
  const isInInactiveContainer = (el: Element): boolean =>
    Boolean(el.closest?.('noscript, template'));

  // 1. metaタグ収集
  const metaTags: Array<{ name?: string; property?: string; content: string }> = [];
  runStep('meta', () => {
    document.querySelectorAll('meta').forEach((el) => {
      const name = el.getAttribute('name') || undefined;
      const property = el.getAttribute('property') || undefined;
      const content = el.getAttribute('content') || '';
      if (content) {
        metaTags.push({ name, property, content });
      }
    });
  });

  // 2. script src 収集（document.baseURI 基準の絶対URLに変換し、元の属性値は rawScriptUrls に保持）(v1.7.1 T05)
  const rawScriptUrls: string[] = [];
  const scriptUrls: string[] = [];
  const domResourceUrls: string[] = [];
  const referenceOnlyUrls: ReferenceOnlyUrlItem[] = [];

  runStep('script[src]', () => {
    document.querySelectorAll('script[src]').forEach((el) => {
      const rawSrc = el.getAttribute('src');
      if (rawSrc && rawSrc.trim()) {
        const trimmed = rawSrc.trim();
        rawScriptUrls.push(trimmed);
        const resolved = resolveToAbsoluteUrl(trimmed, baseUri);
        scriptUrls.push(resolved || trimmed);
        if (resolved && !isInInactiveContainer(el)) {
          domResourceUrls.push(resolved);
        }
      }
    });
  });

  // 3. link href 収集（対象 rel のみ linkUrls / domResourceUrls に入れ、alternate・canonical 等は referenceOnlyUrls に分離）(v1.7.1 T05)
  const rawLinkUrls: Array<{ rel: string; href: string }> = [];
  const linkUrls: Array<{ rel: string; href: string }> = [];
  runStep('link[href]', () => {
    document.querySelectorAll('link[href]').forEach((el) => {
      const rawHref = el.getAttribute('href');
      const rel = el.getAttribute('rel') || '';
      if (rawHref && rawHref.trim()) {
        const trimmed = rawHref.trim();
        rawLinkUrls.push({ rel, href: trimmed });
        const resolved = resolveToAbsoluteUrl(trimmed, baseUri);
        if (isResourceLinkRel(rel)) {
          linkUrls.push({ rel, href: resolved || trimmed });
          if (resolved && !isInInactiveContainer(el)) {
            domResourceUrls.push(resolved);
          }
        } else if (resolved) {
          const relToken = rel.toLowerCase().trim().split(/\s+/).filter(Boolean)[0] || 'link';
          referenceOnlyUrls.push({ sourceType: relToken, url: resolved });
        }
      }
    });
  });

  // 3b. その他のDOMサブリソース要素（img, iframe, video, audio, source, embed, object）の解決済みURL収集 (v1.7.1 T05)
  runStep('domResources', () => {
    document
      .querySelectorAll('img[src], iframe[src], video[src], audio[src], source[src], embed[src]')
      .forEach((el) => {
        if (isInInactiveContainer(el)) return;
        const rawSrc = el.getAttribute('src');
        const resolved = resolveToAbsoluteUrl(rawSrc, baseUri);
        if (resolved) {
          domResourceUrls.push(resolved);
        }
      });

    document.querySelectorAll('img[srcset], source[srcset]').forEach((el) => {
      if (isInInactiveContainer(el)) return;
      if (el.getAttribute('src')) return;
      const srcset = el.getAttribute('srcset');
      if (!srcset) return;
      const firstCandidate = srcset.split(',')[0]?.trim().split(/\s+/)[0];
      const resolved = resolveToAbsoluteUrl(firstCandidate, baseUri);
      if (resolved) {
        domResourceUrls.push(resolved);
      }
    });

    document.querySelectorAll('object[data]').forEach((el) => {
      if (isInInactiveContainer(el)) return;
      const rawData = el.getAttribute('data');
      const resolved = resolveToAbsoluteUrl(rawData, baseUri);
      if (resolved) {
        domResourceUrls.push(resolved);
      }
    });

    // 3c. form[action] は送信先（参照のみ）として記録し、通信先には入れない (v1.7.1 T05)
    document.querySelectorAll('form[action]').forEach((el) => {
      if (isInInactiveContainer(el)) return;
      const rawAction = el.getAttribute('action');
      const resolved = resolveToAbsoluteUrl(rawAction, baseUri);
      if (resolved) {
        referenceOnlyUrls.push({ sourceType: 'form', url: resolved });
      }
    });
  });

  // 3d. Performance Resource Timing API で実際に読み込まれたリソースを収集 (v1.7.1 T05 / E2)
  const resourceEntries: ObservedResourceEntry[] = [];
  runStep('resourceTiming', () => {
    if (typeof performance !== 'undefined' && typeof performance.getEntriesByType === 'function') {
      const entries = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          if (!entry || typeof entry.name !== 'string') continue;
          const resolved = resolveToAbsoluteUrl(entry.name, baseUri);
          if (resolved) {
            resourceEntries.push({
              url: resolved,
              initiatorType:
                typeof entry.initiatorType === 'string' && entry.initiatorType.trim()
                  ? entry.initiatorType.trim()
                  : 'other',
            });
          }
        }
      }
    }
  });

  // 4. 特徴的なDOMマーカーの探査
  const domMarkers: string[] = [];

  // 属性プレフィックス判定 (Vue data-v-, Astro data-astro-cid-, SvelteKit, Angular _nghost-/_ngcontent-, Drupal data-drupal- 等)
  const checkAttrPrefix = (prefix: string): boolean => {
    try {
      if (typeof document.evaluate === 'function' && typeof XPathResult !== 'undefined') {
        const xpath = `//@*[starts-with(name(), '${prefix}')]`;
        const res = document.evaluate(xpath, document, null, XPathResult.BOOLEAN_TYPE, null);
        if (res.booleanValue) return true;
      }
    } catch {
      // XPath例外防止
    }
    const sampleNodes = document.querySelectorAll(
      'body, div, main, header, section, form, script, [id], #app, #root, body > *, body > * > *'
    );
    for (let i = 0; i < Math.min(sampleNodes.length, 100); i++) {
      const attrs = sampleNodes[i].attributes;
      for (let j = 0; j < attrs.length; j++) {
        if (attrs[j].name.startsWith(prefix)) return true;
      }
    }
    return false;
  };

  runStep('domMarkers', () => {
    if (checkAttrPrefix('data-v-')) {
      domMarkers.push('data-v-');
    }
    if (checkAttrPrefix('data-astro-cid-')) {
      domMarkers.push('data-astro-cid-');
    }
    if (checkAttrPrefix('data-sveltekit-')) {
      domMarkers.push('data-sveltekit-');
    }
    if (checkAttrPrefix('_nghost-')) {
      domMarkers.push('_nghost-');
    }
    if (checkAttrPrefix('_ngcontent-')) {
      domMarkers.push('_ngcontent-');
    }
    if (checkAttrPrefix('data-drupal-')) {
      domMarkers.push('data-drupal-');
    }

    // noscript タグ内のテキスト走査 (JS有効時のGTM noscriptフォールバック要素探査)
    try {
      document.querySelectorAll('noscript').forEach((el) => {
        const text = (el.textContent || '') + ' ' + (el.innerHTML || '');
        if (text.includes('googletagmanager.com/ns.html')) {
          domMarkers.push('googletagmanager.com/ns.html');
        }
      });
    } catch {
      // 例外防止
    }

    // 4b. 自動生成されたルール定義に基づくDOMマーカーセレクタの自動探査 (T06 / DOC-01)
    const markerSelectors = Array.from(
      new Set([...DOM_MARKER_SELECTORS, '#root', '#app', '#__next'])
    );

    markerSelectors.forEach((sel) => {
      try {
        const el = document.querySelector(sel);
        if (el) {
          if (sel === '[ng-version]') {
            domMarkers.push(`ng-version="${el.getAttribute('ng-version')}"`);
          } else if (sel === 'script#__NEXT_DATA__') {
            domMarkers.push('__NEXT_DATA__');
          } else if (sel === 'script#__NUXT_DATA__') {
            domMarkers.push('__NUXT_DATA__');
          } else if (sel === "meta[name='csrf-param']") {
            // Rails meta[name='csrf-param'] は content属性値も含めてマーカーに追加 (T06 / DOC-01)
            domMarkers.push(sel);
            const content = el.getAttribute('content');
            if (content) {
              domMarkers.push(content);
            }
          } else if (sel === 'iframe') {
            // GTM 等の iframe シグナル: セレクタ自体に加え、iframe の src 属性値もマーカーに含める
            domMarkers.push(sel);
            try {
              const iframes = document.querySelectorAll('iframe');
              iframes.forEach((iframeEl, idx) => {
                if (idx < 10) {
                  const src = iframeEl.getAttribute('src');
                  if (src) {
                    domMarkers.push(src);
                  }
                }
              });
            } catch {
              // 例外防止
            }
          } else {
            domMarkers.push(sel);
          }
        }
      } catch {
        // セレクタ評価例外防止（無効なセレクタ文字列等は安全にスキップ）
      }
    });
  });

  // 5. HTMLスニペット（Tailwind等のユーティリティクラス探査用）
  const htmlSnippets: string[] = [];
  runStep('htmlSnippets', () => {
    const sampleElements = document.querySelectorAll('body, div, nav, header, main, section');
    sampleElements.forEach((el, index) => {
      if (index < 30) {
        const className = el.getAttribute('class');
        if (className) {
          htmlSnippets.push(className);
        }
      }
    });
  });

  // 5b. 特定要素テキスト収集 (T06 / DOC-01: Spring Boot Whitelabel Error Page 等のテキスト判定用)
  const elementTexts: string[] = [];
  runStep('elementTexts', () => {
    const textElements = document.querySelectorAll('h1, h2, [class*="error"], [id*="error"]');
    textElements.forEach((el, index) => {
      if (index < 10) {
        const text = (el.textContent || '').trim().slice(0, 200);
        if (text) {
          elementTexts.push(text);
        }
      }
    });
  });

  // 6. 混在コンテンツ (Mixed Content) の収集 (v1.7.0 T07 / SPEC-15)
  const mixedContent: MixedContentItem[] = [];
  if (isPageHttps) {
    runStep('mixedContent', () => {
      const extractHttpUrlsFromSrcset = (srcset: string | null): string[] => {
        if (!srcset) return [];
        const urls: string[] = [];
        srcset.split(',').forEach((candidate) => {
          const trimmed = candidate.trim();
          if (!trimmed) return;
          const urlToken = trimmed.split(/\s+/)[0];
          if (urlToken && urlToken.startsWith('http://')) {
            urls.push(urlToken);
          }
        });
        return urls;
      };

      document.querySelectorAll('img[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'image', url: src });
        }
      });

      document.querySelectorAll('img[srcset]').forEach((el) => {
        const urls = extractHttpUrlsFromSrcset(el.getAttribute('srcset'));
        urls.forEach((url) => {
          mixedContent.push({ resourceType: 'image', url });
        });
      });

      document.querySelectorAll('video[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'video', url: src });
        }
      });

      document.querySelectorAll('audio[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'audio', url: src });
        }
      });

      document.querySelectorAll('source[src], source[srcset]').forEach((el) => {
        const parentTag = el.parentElement?.tagName.toLowerCase();
        const srcType: MixedContentItem['resourceType'] =
          parentTag === 'audio' ? 'audio' : parentTag === 'picture' ? 'image' : 'video';

        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: srcType, url: src });
        }

        const srcsetUrls = extractHttpUrlsFromSrcset(el.getAttribute('srcset'));
        srcsetUrls.forEach((url) => {
          mixedContent.push({
            resourceType: parentTag === 'audio' ? 'audio' : parentTag === 'video' ? 'video' : 'image',
            url,
          });
        });
      });

      document.querySelectorAll('script[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'script', url: src });
        }
      });

      document.querySelectorAll('link[rel="stylesheet"][href]').forEach((el) => {
        const href = el.getAttribute('href');
        if (href && href.startsWith('http://')) {
          mixedContent.push({ resourceType: 'stylesheet', url: href });
        }
      });

      document.querySelectorAll('iframe[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'iframe', url: src });
        }
      });

      document.querySelectorAll('object[data]').forEach((el) => {
        const data = el.getAttribute('data');
        if (data && data.startsWith('http://')) {
          mixedContent.push({ resourceType: 'object', url: data });
        }
      });

      document.querySelectorAll('embed[src]').forEach((el) => {
        const src = el.getAttribute('src');
        if (src && src.startsWith('http://')) {
          mixedContent.push({ resourceType: 'embed', url: src });
        }
      });

      document.querySelectorAll('form[action]').forEach((el) => {
        const action = el.getAttribute('action');
        if (action && action.startsWith('http://')) {
          mixedContent.push({ resourceType: 'form', url: action });
        }
      });
    });
  }

  // 7. document.cookieから名前のみ抽出 (値は除外)
  const cookiesFromDocument: string[] = [];
  runStep('cookiesFromDocument', () => {
    const rawCookies = document.cookie || '';
    if (rawCookies) {
      rawCookies.split(';').forEach((pair) => {
        const trimmed = pair.trim();
        const equalsIndex = trimmed.indexOf('=');
        const name = equalsIndex > -1 ? trimmed.substring(0, equalsIndex).trim() : trimmed;
        if (name && !cookiesFromDocument.includes(name)) {
          cookiesFromDocument.push(name);
        }
      });
    }
  });

  // 8. CSSアセット解析 (Version 1.1 ADD-02 / v1.7.1 T05)
  let cssAssets: InspectedCssAsset[] = [];
  runStep('cssAssets', () => {
    cssAssets = inspectCssAssets(baseUri);
  });

  // 9. meta CSP の収集 (Rev.2.1 IMP-05 / v1.7.0 T06: Report-Only を分離収集)
  const metaCsp: string[] = [];
  const metaCspReportOnly: string[] = [];
  runStep('metaCsp', () => {
    const metaCspElements = document.querySelectorAll<HTMLMetaElement>('meta[http-equiv]');
    metaCspElements.forEach((el) => {
      const httpEquiv = (el.getAttribute('http-equiv') || '').trim().toLowerCase();
      const content = el.getAttribute('content');
      if (!content || !content.trim()) return;
      if (httpEquiv === 'content-security-policy') {
        metaCsp.push(content.trim());
      } else if (httpEquiv === 'content-security-policy-report-only') {
        metaCspReportOnly.push(content.trim());
      }
    });
  });

  return {
    url: pageUrl,
    title: typeof document !== 'undefined' ? document.title || '' : '',
    metaTags,
    scriptUrls,
    linkUrls,
    rawScriptUrls,
    rawLinkUrls,
    resourceEntries,
    domResourceUrls,
    referenceOnlyUrls,
    domMarkers,
    htmlSnippets,
    mixedContent,
    cookiesFromDocument,
    cssAssets,
    metaCsp,
    metaCspReportOnly,
    elementTexts,
    ...(collectionErrors.length > 0
      ? {
          collectionPartial: true,
          collectionErrors,
        }
      : {}),
  };
}
