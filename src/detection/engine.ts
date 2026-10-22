/**
 * Web Technology & Security Inspector
 * 拡張技術検出エンジン (src/detection/engine.ts) - Version 1.1.0
 * JavaScript実行時バージョン、CSS解析、整合性確認、EOL・CVE照合を統合
 */

import { checkCveAdvisories } from '../security/cve/cve-engine';
import { checkEolStatus } from '../security/eol/eol-engine';
import {
  DetectedTechnology,
  DomSignals,
  Evidence,
  NetworkSignals,
  VersionIntegrityInfo,
  VersionMismatchStatus,
} from '../shared/types';
import { calculateConfidence } from './confidence';
import { ALL_TECHNOLOGY_RULES, TechnologyRule } from './rules';

export interface DetectionInput {
  url: string;
  dom: DomSignals;
  network?: NetworkSignals;
  runtimeVersions?: Record<string, string | null>;
}

export class DetectionEngine {
  private rules: TechnologyRule[];

  constructor(customRules?: TechnologyRule[]) {
    this.rules = customRules || ALL_TECHNOLOGY_RULES;
  }

  /**
   * 観測情報から技術を特定し、EOLおよびCVE既知脆弱性情報を照合する
   */
  public detect(input: DetectionInput): DetectedTechnology[] {
    const results: DetectedTechnology[] = [];
    const urlObj = this.parseUrl(input.url);
    const runtime = input.runtimeVersions || input.dom?.runtimeVersions || {};

    for (const rule of this.rules) {
      const evidences: Evidence[] = [];
      let detectedVersion: string | null = null;
      let versionSource: string | undefined = undefined;
      let jsVersion: string | null = null;
      let cssVersion: string | null = null;

      // --- A. JavaScript 実行時バージョンのチェック (ADD-01) ---
      if (rule.id === 'jquery' && runtime.jquery) {
        jsVersion = runtime.jquery;
        detectedVersion = runtime.jquery;
        versionSource = 'runtime';
        evidences.push({
          type: 'runtime',
          name: 'window.jQuery.fn.jquery',
          value: runtime.jquery,
          source: 'window.jQuery.fn.jquery',
          detail: `JavaScript実行環境からjQuery ${runtime.jquery} を直接検出`,
          confidence: 'high',
          weight: 100,
        });
      }

      if (rule.id === 'bootstrap') {
        const bsVer = runtime.bootstrap5 || runtime.bootstrap4;
        if (bsVer) {
          jsVersion = bsVer;
          detectedVersion = bsVer;
          versionSource = 'runtime';
          const srcName = runtime.bootstrap5 ? 'window.bootstrap.Modal.VERSION' : 'jQuery.fn.modal.Constructor.VERSION';
          evidences.push({
            type: 'runtime',
            name: srcName,
            value: bsVer,
            source: srcName,
            detail: `JavaScript実行環境からBootstrap JS ${bsVer} を直接検出`,
            confidence: 'high',
            weight: 100,
          });
        }
      }

      if (rule.id === 'vue' && runtime.vue) {
        jsVersion = runtime.vue;
        detectedVersion = runtime.vue;
        versionSource = 'runtime';
        evidences.push({
          type: 'runtime',
          name: 'window.Vue.version',
          value: runtime.vue,
          source: 'window.Vue.version',
          detail: `JavaScript実行環境からVue ${runtime.vue} を直接検出`,
          confidence: 'high',
          weight: 100,
        });
      }

      if (rule.id === 'lodash' && runtime.lodash) {
        jsVersion = runtime.lodash;
        detectedVersion = runtime.lodash;
        versionSource = 'runtime';
        evidences.push({
          type: 'runtime',
          name: 'window._.VERSION',
          value: runtime.lodash,
          source: 'window._.VERSION',
          detail: `JavaScript実行環境からLodash ${runtime.lodash} を直接検出`,
          confidence: 'high',
          weight: 100,
        });
      }

      if (rule.id === 'moment' && runtime.moment) {
        jsVersion = runtime.moment;
        detectedVersion = runtime.moment;
        versionSource = 'runtime';
        evidences.push({
          type: 'runtime',
          name: 'window.moment.version',
          value: runtime.moment,
          source: 'window.moment.version',
          detail: `JavaScript実行環境からMoment.js ${runtime.moment} を直接検出`,
          confidence: 'high',
          weight: 100,
        });
      }

      // --- B. CSSアセット解析 (ADD-02) ---
      if (input.dom?.cssAssets) {
        for (const css of input.dom.cssAssets) {
          if (
            css.inferredLibrary &&
            (css.inferredLibrary.toLowerCase() === rule.name.toLowerCase() ||
              (rule.id === 'bootstrap' && css.inferredLibrary.toLowerCase().includes('bootstrap')))
          ) {
            if (css.inferredVersion) {
              cssVersion = css.inferredVersion;
              if (!detectedVersion) {
                detectedVersion = css.inferredVersion;
                versionSource = css.evidenceType;
              }
            }

            evidences.push({
              type: css.evidenceType,
              name: css.evidenceType === 'css-comment' ? 'CSSファイルコメント' : 'CSSファイルURL',
              value: css.inferredVersion ? `${css.filename} (v${css.inferredVersion})` : css.filename,
              source: css.href,
              detail: `読み込まれたCSSアセットから${rule.name}の特徴を検出`,
              confidence: css.confidence,
              weight: css.confidence === 'high' ? 95 : 80,
            });
          }
        }
      }

      // --- C. ルール照合 (HTTPヘッダー, Cookie, meta, script等) ---
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

                  if (signal.versionRegex && !detectedVersion) {
                    const v = this.extractVersion(val, signal.versionRegex);
                    if (v) {
                      detectedVersion = v;
                      versionSource = 'response-header';
                    }
                  }
                }
              }
            }
            break;
          }

          case 'cookie': {
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
                  name,
                  value: name,
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
                      type: 'html',
                      name: `meta[${targetName}]`,
                      value: meta.content,
                      source: input.url,
                      detail: `metaタグ「${targetName}」にシグネチャを検出`,
                      weight: signal.weight,
                    });

                    if (signal.versionRegex && !detectedVersion) {
                      const v = this.extractVersion(meta.content, signal.versionRegex);
                      if (v) {
                        detectedVersion = v;
                        versionSource = 'html';
                      }
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
                  let scriptVersion: string | null = null;
                  if (signal.versionRegex) {
                    const v = this.extractVersion(scriptSrc, signal.versionRegex);
                    if (v) {
                      scriptVersion = v;
                      if (!detectedVersion) {
                        detectedVersion = v;
                        versionSource = 'script-url';
                      }
                      if (!jsVersion) {
                        jsVersion = v;
                      }
                    }
                  }

                  evidences.push({
                    type: 'script-url',
                    name: 'script[src]',
                    value: scriptVersion ? `${this.truncateUrl(scriptSrc)} (v${scriptVersion})` : this.truncateUrl(scriptSrc),
                    source: scriptSrc,
                    detail: `読み込まれたスクリプトURLにシグネチャを検出`,
                    weight: signal.weight,
                  });
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
                    type: 'css-url',
                    name: `link[rel="${link.rel}"]`,
                    value: this.truncateUrl(link.href),
                    source: link.href,
                    detail: `読み込まれたアセットURLにシグネチャを検出`,
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
                    type: 'html',
                    name: 'DOMマーカー',
                    value: marker,
                    source: input.url,
                    detail: `DOM構造に特有の属性または要素を検出`,
                    weight: signal.weight,
                  });

                  if (signal.versionRegex && !detectedVersion) {
                    const v = this.extractVersion(marker, signal.versionRegex);
                    if (v) {
                      detectedVersion = v;
                      versionSource = 'html';
                    }
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
                    type: 'pattern',
                    name: 'CSSクラスパターン',
                    value: snippet.substring(0, 100),
                    source: input.url,
                    detail: `HTMLクラスにCSSフレームワークの特徴を検出`,
                    weight: signal.weight,
                  });
                }
              }
            }
            break;
          }
        }
      }

      // エビデンスが1件以上検出された場合
      if (evidences.length > 0) {
        const { confidence, level } = calculateConfidence(evidences);

        // --- D. CSS・JavaScriptバージョン整合性判定 (ADD-03) ---
        let versionIntegrity: VersionIntegrityInfo | undefined = undefined;
        if (rule.id === 'bootstrap') {
          versionIntegrity = this.evaluateVersionIntegrity(jsVersion, cssVersion);
        }

        // --- E. EOL・サポート状況判定 (ADD-04) ---
        const eolInfo = checkEolStatus(rule.name, detectedVersion);

        // --- F. 既知脆弱性 (CVE) 照合 (ADD-05) ---
        const cveResult = checkCveAdvisories(rule.name, detectedVersion);

        results.push({
          technology: rule.name,
          category: rule.category,
          detected: true,
          version: detectedVersion,
          versionSource,
          confidence,
          confidenceLevel: level,
          evidence: evidences,
          cssVersion,
          jsVersion,
          versionIntegrity,
          supportStatus: eolInfo.status,
          eolDate: eolInfo.eolDate,
          eolInfo,
          advisoryMatchStatus: cveResult.matchStatus,
          advisories: cveResult.advisories,
          maxCvss: cveResult.maxCvss,
          advisoryDataUpdatedAt: cveResult.updatedAt,
          description: rule.description,
          website: rule.website,
        });
      }
    }

    return results.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * CSSとJSのバージョン整合性を評価する (ADD-03)
   */
  private evaluateVersionIntegrity(
    jsVersion: string | null,
    cssVersion: string | null
  ): VersionIntegrityInfo {
    let status: VersionMismatchStatus = 'indeterminate';
    let detail = 'バージョン情報を両方特定できなかったため、整合性を判定できません。';
    let recommendation = 'CSSおよびJavaScriptのバージョンが正しく揃っているか確認してください。';

    if (jsVersion && cssVersion) {
      if (jsVersion === cssVersion) {
        status = 'match';
        detail = `CSS(${cssVersion}) と JavaScript(${jsVersion}) のバージョンが完全に一致しています。`;
        recommendation = '現状の整合性が保たれています。';
      } else {
        status = 'mismatch';
        detail = `CSS(${cssVersion}) と JavaScript(${jsVersion}) で異なるバージョンが使用されています。`;
        recommendation = 'スタイルの崩れやコンポーネントの挙動不良、潜在的脆弱性を防ぐため、同一バージョンの利用を推奨します。';
      }
    } else if (jsVersion && !cssVersion) {
      detail = `JavaScript(${jsVersion}) は検出されましたが、CSS側のバージョンは特定できませんでした。`;
    } else if (!jsVersion && cssVersion) {
      detail = `CSS(${cssVersion}) は検出されましたが、JavaScript側のバージョンは特定できませんでした。`;
    }

    return {
      jsVersion,
      cssVersion,
      status,
      detail,
      recommendation,
    };
  }

  private matchPattern(value: string | undefined, pattern: string | undefined): boolean {
    if (!value || !pattern) return false;
    try {
      const regex = new RegExp(pattern, 'i');
      return regex.test(value);
    } catch {
      return value.toLowerCase().includes(pattern.toLowerCase());
    }
  }

  private extractVersion(value: string, regexPattern: string): string | null {
    try {
      const regex = new RegExp(regexPattern, 'i');
      const match = value.match(regex);
      if (match && match[1]) {
        return match[1].trim();
      }
    } catch {
      // 正規表現例外防止
    }
    return null;
  }

  private parseUrl(url: string): URL | null {
    try {
      return new URL(url);
    } catch {
      return null;
    }
  }

  private truncateUrl(url: string, maxLength = 80): string {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }
}
