/**
 * Web Technology & Security Inspector
 * 技術検出エンジン (src/detection/engine.ts)
 */

import {
  DetectedTechnology,
  DomSignals,
  Evidence,
  NetworkSignals,
} from '../shared/types';
import { calculateConfidence } from './confidence';
import { ALL_TECHNOLOGY_RULES, TechnologyRule } from './rules';

/**
 * 検出エンジンの入力シグナル
 */
export interface DetectionInput {
  url: string;
  dom: DomSignals;
  network?: NetworkSignals;
}

/**
 * 技術検出エンジン本体
 */
export class DetectionEngine {
  private rules: TechnologyRule[];

  constructor(customRules?: TechnologyRule[]) {
    this.rules = customRules || ALL_TECHNOLOGY_RULES;
  }

  /**
   * 観測されたDOMおよびネットワークシグナルから技術を特定する
   *
   * @param input DOMシグナルおよびネットワークシグナル
   * @returns 検出されたWeb技術一覧
   */
  public detect(input: DetectionInput): DetectedTechnology[] {
    const results: DetectedTechnology[] = [];
    const urlObj = this.parseUrl(input.url);

    for (const rule of this.rules) {
      const evidences: Evidence[] = [];
      let detectedVersion: string | null = null;

      for (const signal of rule.signals) {
        switch (signal.type) {
          case 'header': {
            if (input.network?.responseHeaders) {
              const headerKey = signal.target.toLowerCase();
              const headerValues = input.network.responseHeaders[headerKey] || [];
              for (const val of headerValues) {
                if (this.matchPattern(val, signal.pattern)) {
                  evidences.push({
                    type: 'response-header',
                    name: signal.target,
                    value: val,
                    source: input.url,
                    detail: `HTTPレスポンスヘッダー「${signal.target}」にシグネチャを検出`,
                    weight: signal.weight,
                  });

                  // バージョン抽出
                  if (signal.versionRegex && !detectedVersion) {
                    const v = this.extractVersion(val, signal.versionRegex);
                    if (v) detectedVersion = v;
                  }
                }
              }
            }
            break;
          }

          case 'cookie': {
            // ネットワークから取得したCookieまたはDOMから取得したCookie名
            const cookieNames: string[] = [];
            if (input.network?.cookies) {
              cookieNames.push(...input.network.cookies.map((c) => c.name));
            }
            if (input.dom?.cookiesFromDocument) {
              cookieNames.push(...input.dom.cookiesFromDocument);
            }

            for (const name of cookieNames) {
              if (this.matchPattern(name, signal.pattern || signal.target)) {
                evidences.push({
                  type: 'cookie-name',
                  name: name,
                  value: name, // ※値そのものは保存・出力しない
                  source: input.url,
                  detail: `Cookie「${name}」の存在を検出`,
                  weight: signal.weight,
                });
              }
            }
            break;
          }

          case 'url': {
            const pathAndQuery = urlObj ? `${urlObj.pathname}${urlObj.search}` : '';
            if (this.matchPattern(pathAndQuery, signal.pattern)) {
              evidences.push({
                type: 'url-pattern',
                name: 'URLパス',
                value: pathAndQuery,
                source: input.url,
                detail: `URLパスに固有のシグネチャ「${signal.pattern}」を検出`,
                weight: signal.weight,
              });
            }
            break;
          }

          case 'meta': {
            if (input.dom?.metaTags) {
              for (const meta of input.dom.metaTags) {
                const targetName = (meta.name || meta.property || '').toLowerCase();
                if (targetName === signal.target.toLowerCase()) {
                  if (this.matchPattern(meta.content, signal.pattern)) {
                    evidences.push({
                      type: 'meta-tag',
                      name: `meta[${targetName}]`,
                      value: meta.content,
                      source: input.url,
                      detail: `metaタグ「${targetName}」にシグネチャを検出`,
                      weight: signal.weight,
                    });

                    if (signal.versionRegex && !detectedVersion) {
                      const v = this.extractVersion(meta.content, signal.versionRegex);
                      if (v) detectedVersion = v;
                    }
                  }
                }
              }
            }
            break;
          }

          case 'script': {
            if (input.dom?.scriptUrls) {
              for (const scriptSrc of input.dom.scriptUrls) {
                if (this.matchPattern(scriptSrc, signal.pattern)) {
                  evidences.push({
                    type: 'script-src',
                    name: 'script[src]',
                    value: this.truncateUrl(scriptSrc),
                    source: scriptSrc,
                    detail: `読み込まれたスクリプトURLにシグネチャを検出`,
                    weight: signal.weight,
                  });

                  if (signal.versionRegex && !detectedVersion) {
                    const v = this.extractVersion(scriptSrc, signal.versionRegex);
                    if (v) detectedVersion = v;
                  }
                }
              }
            }
            break;
          }

          case 'link': {
            if (input.dom?.linkUrls) {
              for (const link of input.dom.linkUrls) {
                if (this.matchPattern(link.href, signal.pattern)) {
                  evidences.push({
                    type: 'link-href',
                    name: `link[rel="${link.rel}"]`,
                    value: this.truncateUrl(link.href),
                    source: link.href,
                    detail: `読み込まれたリソースURLにシグネチャを検出`,
                    weight: signal.weight,
                  });
                }
              }
            }
            break;
          }

          case 'dom': {
            if (input.dom?.domMarkers) {
              for (const marker of input.dom.domMarkers) {
                if (this.matchPattern(marker, signal.pattern)) {
                  evidences.push({
                    type: 'dom-marker',
                    name: 'DOMマーカー',
                    value: marker,
                    source: input.url,
                    detail: `DOM構造に特有の属性または要素を検出`,
                    weight: signal.weight,
                  });

                  if (signal.versionRegex && !detectedVersion) {
                    const v = this.extractVersion(marker, signal.versionRegex);
                    if (v) detectedVersion = v;
                  }
                }
              }
            }
            break;
          }

          case 'css': {
            if (input.dom?.htmlSnippets) {
              for (const snippet of input.dom.htmlSnippets) {
                if (this.matchPattern(snippet, signal.pattern)) {
                  evidences.push({
                    type: 'css-rule',
                    name: 'CSSスタイル・クラス',
                    value: snippet.substring(0, 100),
                    source: input.url,
                    detail: `HTMLクラス・スタイルにCSSフレームワークの特徴を検出`,
                    weight: signal.weight,
                  });
                }
              }
            }
            break;
          }
        }
      }

      // エビデンスが検出された場合のみ技術として記録
      if (evidences.length > 0) {
        const { confidence, level } = calculateConfidence(evidences);
        results.push({
          technology: rule.name,
          category: rule.category,
          detected: true,
          version: detectedVersion,
          confidence,
          confidenceLevel: level,
          evidence: evidences,
          description: rule.description,
          website: rule.website,
        });
      }
    }

    // 確信度降順、カテゴリ順でソート
    return results.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * 文字列が正規表現または部分一致でマッチするか判定
   */
  private matchPattern(value: string | undefined, pattern: string | undefined): boolean {
    if (!value || !pattern) return false;
    try {
      const regex = new RegExp(pattern, 'i');
      return regex.test(value);
    } catch {
      return value.toLowerCase().includes(pattern.toLowerCase());
    }
  }

  /**
   * 正規表現パターンからバージョン番号を抽出する
   */
  private extractVersion(value: string, regexPattern: string): string | null {
    try {
      const regex = new RegExp(regexPattern, 'i');
      const match = value.match(regex);
      if (match && match[1]) {
        return match[1].trim();
      }
    } catch {
      // 正規表現エラー時は無視
    }
    return null;
  }

  /**
   * URL文字列を安全にパース
   */
  private parseUrl(url: string): URL | null {
    try {
      return new URL(url);
    } catch {
      return null;
    }
  }

  /**
   * 長いURLの表示用トリミング
   */
  private truncateUrl(url: string, maxLength = 80): string {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }
}
