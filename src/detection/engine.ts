/**
 * Web Technology & Security Inspector
 * 拡張技術検出エンジン (src/detection/engine.ts) - Version 1.1.0
 * JavaScript実行時バージョン、CSS解析、整合性確認、EOL・CVE照合を統合
 */

import { checkCveAdvisories } from '../security/cve/cve-engine';
import { checkEolStatus } from '../security/eol/eol-engine';
import { matchOfflineAdvisories } from './advisory';
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

      if (rule.id === 'angularjs' && runtime.angularjs) {
        jsVersion = runtime.angularjs;
        detectedVersion = runtime.angularjs;
        versionSource = 'runtime';
        evidences.push({
          type: 'runtime',
          name: 'window.angular.version.full',
          value: runtime.angularjs,
          source: 'window.angular.version.full',
          detail: `JavaScript実行環境からAngularJS ${runtime.angularjs} を直接検出`,
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
                    detail: signal.detail || `HTTPレスポンスヘッダー「${signal.target}」にシグネチャを検出`,
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
                  detail: signal.detail || `Cookie「${name}」の存在を検出`,
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
                detail: signal.detail || `URLパスに固有のシグネチャ「${signal.pattern}」を検出`,
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
                      detail: signal.detail || `metaタグ「${targetName}」にシグネチャを検出`,
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
                    detail: signal.detail || `読み込まれたスクリプトURLにシグネチャを検出`,
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
                  let linkVersion: string | null = null;
                  if (signal.versionRegex) {
                    const v = this.extractVersion(link.href, signal.versionRegex);
                    if (v) {
                      linkVersion = v;
                      if (!detectedVersion) {
                        detectedVersion = v;
                        versionSource = 'html';
                      }
                    }
                  }

                  evidences.push({
                    type: 'css-url',
                    name: `link[rel="${link.rel}"]`,
                    value: linkVersion ? `${this.truncateUrl(link.href)} (v${linkVersion})` : this.truncateUrl(link.href),
                    source: link.href,
                    detail: signal.detail || `読み込まれたアセットURLにシグネチャを検出`,
                    weight: signal.weight,
                  });
                }
              }
            }
            break;
          }

          case 'dom': {
            // ページタイトルの検査 (例: FastAPI Swagger UI)
            if (signal.target === 'title' && input.dom?.title) {
              if (this.matchPattern(input.dom.title, signal.pattern)) {
                evidences.push({
                  type: 'html',
                  name: 'ページタイトル',
                  value: input.dom.title,
                  source: input.url,
                  detail: signal.detail || `ページタイトルから特徴を検出`,
                  weight: signal.weight,
                });
              }
            }

            // 特徴的DOMマーカーの検査
            if (input.dom?.domMarkers) {
              for (const marker of input.dom.domMarkers) {
                if (this.matchPattern(marker, signal.pattern)) {
                  evidences.push({
                    type: 'html',
                    name: 'DOMマーカー',
                    value: marker,
                    source: input.url,
                    detail: signal.detail || `DOM構造に特有の属性または要素を検出`,
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

            // HTMLスニペット/bodyコンテンツの検査 (属性セレクタ [attr] やフォーム要素は domMarkers でのみ評価)
            const isAttrSelector = signal.target.includes('[') || signal.target.includes('input[') || signal.target.includes('meta[');
            if (input.dom?.htmlSnippets && signal.target !== 'title' && !isAttrSelector) {
              for (const snippet of input.dom.htmlSnippets) {
                if (this.matchPattern(snippet, signal.pattern)) {
                  evidences.push({
                    type: 'html',
                    name: 'HTMLコンテンツ',
                    value: snippet.substring(0, 50),
                    source: input.url,
                    detail: signal.detail || `HTMLコンテンツから特徴を検出`,
                    weight: signal.weight,
                  });
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
                    detail: signal.detail || `HTMLクラスにCSSフレームワークの特徴を検出`,
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

        // --- E/F. オフラインEOL・既知脆弱性 (CVE) 照合 (IMP-03 / ADD-04 / ADD-05) ---
        const offlineResult = matchOfflineAdvisories(rule.name, detectedVersion);
        const eolInfo =
          offlineResult.eolInfo.status !== 'Unknown'
            ? offlineResult.eolInfo
            : checkEolStatus(rule.name, detectedVersion);
        const cveResult =
          offlineResult.matchStatus !== 'No Data'
            ? offlineResult
            : checkCveAdvisories(rule.name, detectedVersion);

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
          offlineMatchStatus: offlineResult.offlineMatchStatus,
          isStale: offlineResult.isStale,
          dbFreshness: offlineResult.dbFreshness,
          advisories: cveResult.advisories,
          maxCvss: cveResult.maxCvss,
          advisoryDataUpdatedAt: cveResult.updatedAt,
          description: rule.description,
          website: rule.website,
          detectionMethod: 'direct',
          runtimeStatus: 'confirmed',
        });
      }
    }

    // --- 連動検知フェーズ (Implication Resolver) ---
    this.resolveImplications(results, input);

    // --- 複数候補の集約・抑制フェーズ (Candidate Consolidation & Suppression) ---
    this.consolidateCandidates(results, input);

    // --- 採用しきい値フィルタ (確信度50%未満の不確定な単独検出を抑制。ただし複数候補集約は保持) ---
    const filteredResults = results.filter(
      (r) => r.confidence >= 50 || r.technology.includes('(候補)')
    );

    return filteredResults.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * XSRF-TOKEN等による汎用Cookieの複数候補を集約または抑制する
   */
  private consolidateCandidates(results: DetectedTechnology[], input: DetectionInput): void {
    // 0. Laravel の汎用セッションCookie（*_session）の組み合わせ検査
    // XSRF-TOKEN を伴わない単独の *_session は誤検知防止のため抑制
    // *_session と XSRF-TOKEN の両方が揃っている場合は確信度70%として確定
    const laravelIndex = results.findIndex((r) => r.technology === 'Laravel');
    if (laravelIndex >= 0) {
      const laravelItem = results[laravelIndex];
      const hasStrictSignal = laravelItem.evidence.some(
        (e) => e.name === 'laravel_session' || e.name === 'x-powered-by'
      );
      const hasGenericSession = laravelItem.evidence.some(
        (e) => /^[a-zA-Z0-9_-]+_session$/.test(e.name) && e.name !== 'laravel_session'
      );
      const hasXsrfToken = laravelItem.evidence.some((e) => e.name === 'XSRF-TOKEN');

      if (!hasStrictSignal && hasGenericSession) {
        if (!hasXsrfToken) {
          // XSRF-TOKEN を伴わない単独の汎用 *_session は不確定のため抑制
          results.splice(laravelIndex, 1);
        } else {
          // 両方揃っている場合は確信度70%として確定採用
          laravelItem.confidence = 70;
          laravelItem.confidenceLevel = 'medium';
        }
      }
    }

    const candidateTechNames = ['Java', 'Laravel', 'Node.js'];

    // 候補技術のうち、結果に含まれているものを抽出
    const matchedCandidates = results.filter((r) =>
      candidateTechNames.includes(r.technology)
    );

    if (matchedCandidates.length === 0) return;

    // 「XSRF-TOKEN のみの検出（確信度35%かつエビデンスがXSRF-TOKENのみ）」かどうかを判定するヘルパー
    const isOnlyXsrfToken = (tech: DetectedTechnology): boolean => {
      return (
        tech.confidence <= 35 &&
        tech.evidence.length === 1 &&
        tech.evidence[0].name === 'XSRF-TOKEN'
      );
    };

    // 本命シグナル（確信度 > 35% または XSRF-TOKEN以外のシグナルがある）を持つ技術があるか？
    const hasDefinitiveSignal = matchedCandidates.some((r) => !isOnlyXsrfToken(r));

    if (hasDefinitiveSignal) {
      // 本命の技術が存在する場合（例: laravel_session で Laravel が検出された場合など）
      // XSRF-TOKEN のみでヒットした他言語は本命技術のCookie発行とみなして抑制（削除）する
      for (let i = results.length - 1; i >= 0; i--) {
        const item = results[i];
        if (candidateTechNames.includes(item.technology) && isOnlyXsrfToken(item)) {
          results.splice(i, 1);
        }
      }
    } else {
      // どの候補も XSRF-TOKEN のみの場合
      const xsrfOnlyItems = matchedCandidates.filter(isOnlyXsrfToken);

      // 2件以上が XSRF-TOKEN のみで競合している場合、1行に集約
      if (xsrfOnlyItems.length >= 2) {
        // 個別の候補を results から削除
        for (let i = results.length - 1; i >= 0; i--) {
          const item = results[i];
          if (candidateTechNames.includes(item.technology) && isOnlyXsrfToken(item)) {
            results.splice(i, 1);
          }
        }

        // 1つの統合された候補技術オブジェクトを追加
        results.push({
          technology: 'Java / Laravel / Node.js (候補)',
          category: 'programming-language',
          detected: true,
          version: null,
          versionSource: 'candidate',
          confidence: 35,
          confidenceLevel: 'low',
          isCandidateGroup: true,
          candidateTechnologies: ['Java (Spring Boot)', 'Laravel (PHP)', 'Node.js (Express)'],
          detectionMethod: 'associated',
          runtimeStatus: 'possible',
          evidence: [
            {
              type: 'cookie-name',
              name: 'XSRF-TOKEN',
              value: 'XSRF-TOKEN',
              source: input.url,
              detail:
                'Cookie「XSRF-TOKEN」を検出（Spring Security, Laravel, Express等のSPA構成で広く使われるため、いずれかが稼働している可能性あり）',
              confidence: 'low',
              weight: 35,
            },
          ],
          supportStatus: 'Unknown',
          eolInfo: {
            status: 'Unknown',
            eolDate: null,
            source: '推定候補',
            recommendation: '稼働しているバックエンド環境の特定を推奨',
          },
          advisoryMatchStatus: 'No Data',
          offlineMatchStatus: 'Not Covered',
          description:
            'SPAと連携するバックエンドフレームワーク（Spring Boot, Laravel, Express等）で広く採用されているCSRF保護Cookie。いずれかのフレームワークが稼働している可能性があります。',
        });
      }
    }
  }

  /**
   * 確信度50%以上の技術から連動技術（含意関係）を解決する (Rev.1.2 IMP-17)
   */
  private resolveImplications(results: DetectedTechnology[], input: DetectionInput): void {
    // 循環防止のための訪問履歴 (triggerId -> impliedId)
    const visitedEdges = new Set<string>();

    // 最大2パス実行して連鎖的な連動も解決
    for (let pass = 0; pass < 2; pass++) {
      let addedOrUpdated = false;

      // 確信度50%（Medium以上）の技術のみをトリガーとする
      const eligibleTriggers = results.filter((r) => r.confidence >= 50);

      for (const trigger of eligibleTriggers) {
        const triggerRule = this.rules.find(
          (rule) =>
            rule.name.toLowerCase() === trigger.technology.toLowerCase() ||
            rule.id.toLowerCase() === trigger.technology.toLowerCase()
        );
        if (!triggerRule || !triggerRule.implies || triggerRule.implies.length === 0) {
          continue;
        }

        for (const rawImp of triggerRule.implies) {
          // 文字列またはオブジェクト形式を正規化
          const impDef = typeof rawImp === 'string'
            ? {
                id: rawImp,
                relation: 'runtime-dependency' as const,
                runtimeStatus: 'unknown' as const,
                confidenceFactor: 0.9,
              }
            : {
                id: rawImp.id,
                relation: rawImp.relation || 'runtime-dependency',
                runtimeStatus: rawImp.runtimeStatus || 'unknown',
                confidenceFactor: rawImp.confidenceFactor ?? 0.9,
              };

          const edgeKey = `${triggerRule.id}->${impDef.id}`;
          if (visitedEdges.has(edgeKey)) {
            continue;
          }
          visitedEdges.add(edgeKey);

          // 静的配信（SSG）配慮: Next.js / Nuxt / SvelteKit からの Node.js 推論は、
          // サーバーサイド（SSR）の明確な証拠（HTTPレスポンスヘッダー等）がある場合のみ発火する
          if (
            impDef.id === 'nodejs' &&
            ['nextjs', 'nuxtjs', 'sveltekit'].includes(triggerRule.id)
          ) {
            const headers = input.network?.responseHeaders;
            const hasSsrHeader =
              headers &&
              (Boolean(headers['x-powered-by']?.some((v) => /Next|Nuxt|Node/i.test(v))) ||
                Boolean(headers['x-nextjs-cache']) ||
                Boolean(headers['x-nitro-cache']) ||
                Boolean(headers['server']?.some((v) => /^Node(?:\.js)?(?:\/|$)/i.test(v))));

            if (!hasSsrHeader) {
              // 静的エクスポート（SSG）の可能性が高いため、サーバーサイドNode.jsの連動推論は行わない
              continue;
            }
          }

          const impliedRule = this.rules.find(
            (rule) => rule.id.toLowerCase() === impDef.id.toLowerCase()
          );
          if (!impliedRule) continue;

          // 自己参照はスキップ
          if (impliedRule.name.toLowerCase() === trigger.technology.toLowerCase()) continue;

          // 関係性に応じた表示ラベル
          let relationLabel = '連動判定';
          if (impDef.relation === 'framework-dependency') {
            relationLabel = 'フレームワーク基盤依存';
          } else if (impDef.relation === 'possible-runtime') {
            relationLabel = '実行環境候補（静的配信等の可能性あり）';
          } else if (impDef.relation === 'runtime-dependency') {
            relationLabel = '実行時依存';
          }

          // 連動先確信度（トリガーが80%以上の場合は80% High、それ以外は係数適用）
          const impliedWeight = trigger.confidence >= 80
            ? 80
            : Math.min(79, Math.max(50, Math.round(trigger.confidence * impDef.confidenceFactor)));

          const impliedEvidence: Evidence = {
            type: 'pattern',
            name: '連動検出 (Implication)',
            value: trigger.technology,
            source: trigger.technology,
            detail: `${trigger.technology}（確信度${trigger.confidence}%）の検出に基づく連動判定 [${relationLabel}]`,
            confidence: impliedWeight >= 80 ? 'high' : 'medium',
            weight: impliedWeight,
          };

          const existingIndex = results.findIndex(
            (r) => r.technology.toLowerCase() === impliedRule.name.toLowerCase()
          );

          if (existingIndex >= 0) {
            // 既に存在する場合：連動エビデンスが未追加なら追加して確信度を再計算
            const existing = results[existingIndex];
            const alreadyHasThisImplication = existing.evidence.some(
              (e) => e.source === trigger.technology && e.type === 'pattern'
            );
            if (!alreadyHasThisImplication) {
              existing.evidence.push(impliedEvidence);
              const recalculated = calculateConfidence(existing.evidence);
              existing.confidence = Math.max(existing.confidence, recalculated.confidence);
              existing.confidenceLevel = recalculated.level;
              if (existing.detectionMethod !== 'direct') {
                existing.detectionMethod = 'inferred';
              }
              if (existing.runtimeStatus !== 'confirmed') {
                existing.runtimeStatus = impDef.runtimeStatus;
              }
              addedOrUpdated = true;
            }
          } else {
            // 存在しない場合：新規追加
            const { confidence, level } = calculateConfidence([impliedEvidence]);
            const offlineResult = matchOfflineAdvisories(impliedRule.name, null);
            const eolInfo =
              offlineResult.eolInfo.status !== 'Unknown'
                ? offlineResult.eolInfo
                : checkEolStatus(impliedRule.name, null);
            const cveResult =
              offlineResult.matchStatus !== 'No Data'
                ? offlineResult
                : checkCveAdvisories(impliedRule.name, null);

            results.push({
              technology: impliedRule.name,
              category: impliedRule.category,
              detected: true,
              version: null,
              versionSource: 'implication',
              confidence,
              confidenceLevel: level,
              evidence: [impliedEvidence],
              supportStatus: eolInfo.status,
              eolDate: eolInfo.eolDate,
              eolInfo,
              advisoryMatchStatus: cveResult.matchStatus,
              offlineMatchStatus: offlineResult.offlineMatchStatus,
              isStale: offlineResult.isStale,
              dbFreshness: offlineResult.dbFreshness,
              advisories: cveResult.advisories,
              maxCvss: cveResult.maxCvss,
              advisoryDataUpdatedAt: cveResult.updatedAt,
              description: impliedRule.description,
              website: impliedRule.website,
              detectionMethod: 'inferred',
              implicationType: impDef.relation,
              inferredFrom: trigger.technology,
              runtimeStatus: impDef.runtimeStatus,
              inferencePath: [trigger.technology, impliedRule.name],
            });
            addedOrUpdated = true;
          }
        }
      }

      if (!addedOrUpdated) {
        break;
      }
    }
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
