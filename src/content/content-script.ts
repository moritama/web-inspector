/**
 * Web Technology & Security Inspector
 * Content Script (src/content/content-script.ts) - Version 1.1.0
 * 閲覧中のWebページ内でDOM、CSSアセット、混在コンテンツを収集します
 */

import { DomSignals, InspectedCssAsset, MixedContentItem } from '../shared/types';
import { DOM_MARKER_SELECTORS } from './dom-selectors.generated';

/**
 * CSSファイル参照（linkタグ）を解析し、ライブラリ名とバージョンを推定する (ADD-02)
 */
function inspectCssAssets(): InspectedCssAsset[] {
  const assets: InspectedCssAsset[] = [];
  const linkElements = document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"][href]');

  linkElements.forEach((link) => {
    const href = link.href;
    if (!href) return;

    let filename = '';
    try {
      const urlObj = new URL(href, window.location.href);
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
        regex: /\/bootstrap[/-]([0-9.]+)\//i,
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
    let evidenceType: 'css-url' | 'css-comment' = 'css-url';
    let confidence: 'high' | 'medium' | 'low' = 'medium';

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

    // 2. CSSコメントからのバージョン抽出 (styleSheets経由の安全なインメモリ確認)
    try {
      for (let i = 0; i < document.styleSheets.length; i++) {
        const sheet = document.styleSheets[i];
        if (sheet.href === href) {
          // 同一オリジン等の理由でアクセス可能な場合、ルールやオーナーノードを検査
          const ownerNode = sheet.ownerNode;
          if (ownerNode && ownerNode.textContent) {
            const commentMatch = ownerNode.textContent.match(
              /\/\*!\s*\*?\s*([A-Za-z0-9_.-]+)\s+v?([0-9.]+)/i
            );
            if (commentMatch) {
              detectedLib = detectedLib || commentMatch[1];
              detectedVersion = commentMatch[2];
              evidenceType = 'css-comment';
              confidence = 'high';
            }
          }
        }
      }
    } catch {
      // クロスオリジンCSS読み取り制限時の例外防止
    }

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
 * ページ内のDOM、スクリプト、メタ情報、混在コンテンツを安全に抽出する
 */
export function extractDomSignals(): DomSignals {
  const isPageHttps = window.location.protocol === 'https:';

  // 1. metaタグ収集
  const metaTags: Array<{ name?: string; property?: string; content: string }> = [];
  document.querySelectorAll('meta').forEach((el) => {
    const name = el.getAttribute('name') || undefined;
    const property = el.getAttribute('property') || undefined;
    const content = el.getAttribute('content') || '';
    if (content) {
      metaTags.push({ name, property, content });
    }
  });

  // 2. script src 収集
  const scriptUrls: string[] = [];
  document.querySelectorAll('script[src]').forEach((el) => {
    const src = el.getAttribute('src');
    if (src) {
      scriptUrls.push(src);
    }
  });

  // 3. link href 収集
  const linkUrls: Array<{ rel: string; href: string }> = [];
  document.querySelectorAll('link[href]').forEach((el) => {
    const href = el.getAttribute('href');
    const rel = el.getAttribute('rel') || '';
    if (href) {
      linkUrls.push({ rel, href });
    }
  });

  // 4. 特徴的なDOMマーカーの探査
  const domMarkers: string[] = [];

  // 属性プレフィックス判定 (Vue data-v-, Astro data-astro-cid-, SvelteKit 等)
  const checkAttrPrefix = (prefix: string): boolean => {
    try {
      if (typeof document.evaluate === 'function') {
        const xpath = `//@*[starts-with(name(), '${prefix}')]`;
        const res = document.evaluate(xpath, document, null, XPathResult.BOOLEAN_TYPE, null);
        if (res.booleanValue) return true;
      }
    } catch {
      // XPath例外防止
    }
    const sampleNodes = document.querySelectorAll('body, div, main, header, section, [id], #app, #root');
    for (let i = 0; i < Math.min(sampleNodes.length, 60); i++) {
      const attrs = sampleNodes[i].attributes;
      for (let j = 0; j < attrs.length; j++) {
        if (attrs[j].name.startsWith(prefix)) return true;
      }
    }
    return false;
  };

  if (checkAttrPrefix('data-v-')) {
    domMarkers.push('data-v-');
  }
  if (checkAttrPrefix('data-astro-cid-')) {
    domMarkers.push('data-astro-cid-');
  }
  if (checkAttrPrefix('data-sveltekit-')) {
    domMarkers.push('data-sveltekit-');
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
  const markerSelectors = Array.from(new Set([...DOM_MARKER_SELECTORS, '#root', '#app', '#__next']));

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

  // 5. HTMLスニペット（Tailwind等のユーティリティクラス探査用）
  const htmlSnippets: string[] = [];
  const sampleElements = document.querySelectorAll('body, div, nav, header, main, section');
  sampleElements.forEach((el, index) => {
    if (index < 30) {
      const className = el.getAttribute('class');
      if (className) {
        htmlSnippets.push(className);
      }
    }
  });

  // 5b. 特定要素テキスト収集 (T06 / DOC-01: Spring Boot Whitelabel Error Page 等のテキスト判定用)
  const elementTexts: string[] = [];
  try {
    const textElements = document.querySelectorAll('h1, h2, [class*="error"], [id*="error"]');
    textElements.forEach((el, index) => {
      if (index < 10) {
        const text = (el.textContent || '').trim().slice(0, 200);
        if (text) {
          elementTexts.push(text);
        }
      }
    });
  } catch {
    // テキスト取得例外防止
  }

  // 6. 混在コンテンツ (Mixed Content) の収集
  const mixedContent: MixedContentItem[] = [];
  if (isPageHttps) {
    document.querySelectorAll('img[src]').forEach((el) => {
      const src = el.getAttribute('src');
      if (src && src.startsWith('http://')) {
        mixedContent.push({ resourceType: 'image', url: src });
      }
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
  }

  // 7. document.cookieから名前のみ抽出 (値は除外)
  const cookiesFromDocument: string[] = [];
  try {
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
  } catch {
    // Cookie読み取り例外防止
  }

  // 8. CSSアセット解析 (Version 1.1 ADD-02)
  const cssAssets = inspectCssAssets();

  // 9. meta CSP の収集 (Rev.2.1 IMP-05)
  const metaCsp: string[] = [];
  try {
    const metaCspElements = document.querySelectorAll<HTMLMetaElement>(
      'meta[http-equiv="Content-Security-Policy" i], meta[http-equiv="Content-Security-Policy-Report-Only" i]'
    );
    metaCspElements.forEach((el) => {
      const content = el.getAttribute('content');
      if (content && content.trim()) {
        metaCsp.push(content.trim());
      }
    });
  } catch {
    // meta取得例外防止
  }

  return {
    url: window.location.href,
    title: document.title || '',
    metaTags,
    scriptUrls,
    linkUrls,
    domMarkers,
    htmlSnippets,
    mixedContent,
    cookiesFromDocument,
    cssAssets,
    metaCsp,
    elementTexts,
  };
}

// Service WorkerまたはPopupからの要求に応答
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'EXTRACT_DOM_SIGNALS') {
      const signals = extractDomSignals();
      sendResponse(signals);
    }
    return true;
  });
}
