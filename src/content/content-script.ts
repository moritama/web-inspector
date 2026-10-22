/**
 * Web Technology & Security Inspector
 * Content Script (src/content/content-script.ts) - Version 1.1.0
 * 閲覧中のWebページ内でDOM、CSSアセット、混在コンテンツを収集します
 */

import { DomSignals, InspectedCssAsset, MixedContentItem } from '../shared/types';

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
  const markerSelectors = [
    '#root',
    '#app',
    '#__next',
    '#__nuxt',
    'script#__NEXT_DATA__',
    'script#__NUXT_DATA__',
    '[data-reactroot]',
    '[data-reactid]',
    '[data-v-]',
    '[ng-version]',
    '[ng-app]',
    '[ng-controller]',
    "[class*='svelte-']",
    "input[name='csrfmiddlewaretoken']",
    "meta[name='csrf-param']",
  ];

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
        } else {
          domMarkers.push(sel);
        }
      }
    } catch {
      // セレクタ評価例外防止
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
  };
}

// Service WorkerまたはPopupからの要求に応答
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'EXTRACT_DOM_SIGNALS') {
    const signals = extractDomSignals();
    sendResponse(signals);
  }
  return true;
});
