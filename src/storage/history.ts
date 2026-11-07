/**
 * Web Technology & Security Inspector
 * 調査履歴ストレージ管理 (src/storage/history.ts)
 */

import { DetectedTechnology, Evidence, HistoryEntrySummary, InspectionReport } from '../shared/types';
import { normalizeCookieCategory } from '../security/cookies';
import { stripUrlQueryAndFragment } from '../shared/identity';

export const STORAGE_KEY_HISTORY = 'web_inspector_history';
export const DEFAULT_MAX_HISTORY = 50;
export const MAX_EVIDENCE_PER_TECH = 20;
export const MAX_SINGLE_REPORT_BYTES = 512 * 1024;
export const MAX_TOTAL_HISTORY_BYTES = 8 * 1024 * 1024;

/**
 * サービスワーカー内の履歴 Read-Modify-Write 競合を防ぐ直列化キュー (v1.7.0 T10 / IMPL-06)
 */
let historyMutationQueue: Promise<void> = Promise.resolve();

function runSerializedHistoryMutation<T>(operation: () => Promise<T>): Promise<T> {
  const resultPromise = historyMutationQueue.then(operation, operation);
  historyMutationQueue = resultPromise.then(
    () => undefined,
    () => undefined
  );
  return resultPromise;
}

/**
 * 文字列中に含まれる http(s) URL からクエリとフラグメントを除去する (IMPL-07)
 */
function maskUrlsInText(text: string | undefined): string {
  if (!text) return '';
  if (/^https?:\/\//i.test(text.trim())) {
    return stripUrlQueryAndFragment(text.trim());
  }
  return text.replace(/https?:\/\/[^\s"'<>)+]+/gi, (match) => stripUrlQueryAndFragment(match));
}

function sanitizeEvidenceItem(ev: Evidence): Evidence {
  return {
    ...ev,
    value: maskUrlsInText(ev.value),
    source: maskUrlsInText(ev.source),
    ...(ev.detail ? { detail: maskUrlsInText(ev.detail) } : {}),
  };
}

/**
 * URLクエリマスク後のエビデンス一覧から、同じ type と value の重複を 1 件にまとめ、
 * ほかに根拠がある場合は汎用クラス（.container 等）のみの根拠を省略する (v1.7.1 T09 / J)
 */
function dedupeAndFilterEvidences(evidences: Evidence[]): Evidence[] {
  if (!Array.isArray(evidences) || evidences.length === 0) return [];
  const isGeneric = (ev: Evidence): boolean => {
    if (!ev) return false;
    if (ev.detail && ev.detail.includes('汎用クラス')) return true;
    if (ev.type === 'html' || ev.type === 'dom-marker' || ev.type === 'pattern') {
      const val = (ev.value || '').trim();
      if (/^\.container\b/i.test(val) || /^(?:(?:sm|md|lg|xl|2xl):)?container$/i.test(val)) {
        return true;
      }
    }
    return false;
  };
  const hasNonGeneric = evidences.some((e) => !isGeneric(e));
  const filtered = hasNonGeneric ? evidences.filter((e) => !isGeneric(e)) : evidences;

  const deduped: Evidence[] = [];
  const seen = new Set<string>();
  for (const ev of filtered) {
    const key = `${ev.type}\0${(ev.value || '').trim()}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(ev);
    }
  }
  return deduped;
}

/**
 * レポート内の URL からクエリパラメータ (?...) とフラグメント (#...) を除去する (v1.7.0 T10 / IMPL-07)
 */
export function sanitizeReportUrls(report: InspectionReport): InspectionReport {
  const maskedUrl = stripUrlQueryAndFragment(report.url);

  const technologies: DetectedTechnology[] = (report.technologies || []).map((tech) => ({
    ...tech,
    evidence: dedupeAndFilterEvidences((tech.evidence || []).map(sanitizeEvidenceItem)),
    ...(tech.instances
      ? {
          instances: tech.instances.map((inst) => ({
            ...inst,
            evidence: dedupeAndFilterEvidences((inst.evidence || []).map(sanitizeEvidenceItem)),
          })),
        }
      : {}),
  }));

  const securityChecks = (report.securityChecks || []).map((check) => ({
    ...check,
    ...(check.scope ? { scope: stripUrlQueryAndFragment(check.scope) } : {}),
    observed: maskUrlsInText(check.observed),
    description: maskUrlsInText(check.description),
  }));

  const mixedContent = (report.mixedContent || []).map((item) => ({
    ...item,
    url: stripUrlQueryAndFragment(item.url),
  }));

  const cookies = (report.cookies || []).map((c) => {
    const normalizedCat = normalizeCookieCategory(c.category);
    return {
      ...c,
      category: normalizedCat,
      ...(c.classification
        ? {
            classification: {
              ...c.classification,
              category: normalizeCookieCategory(c.classification.category ?? c.category),
            },
          }
        : {}),
    };
  });

  const externalConnections = report.externalConnections
    ? {
        ...report.externalConnections,
        connections: (report.externalConnections.connections || []).map((conn) => ({
          ...conn,
          sampleUrls: (conn.sampleUrls || []).map((u) => stripUrlQueryAndFragment(u)),
        })),
      }
    : undefined;

  return {
    ...report,
    url: maskedUrl,
    technologies,
    securityChecks,
    cookies,
    mixedContent,
    ...(externalConnections ? { externalConnections } : {}),
  };
}

/**
 * オブジェクトの UTF-8 JSON バイトサイズを算出する
 */
export function estimateJsonByteSize(value: unknown): number {
  const json = JSON.stringify(value);
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(json).byteLength;
  }
  return json.length * 2;
}

/**
 * 1件あたりのレポートサイズ上限と evidence 件数上限（1技術あたり最大20件）を適用する (v1.7.0 T10 / IMPL-06)
 */
export function enforceReportStorageLimits(
  report: InspectionReport,
  maxSingleReportBytes = MAX_SINGLE_REPORT_BYTES
): InspectionReport {
  const masked = sanitizeReportUrls(report);

  const trimmedTechnologies: DetectedTechnology[] = (masked.technologies || []).map((tech) => ({
    ...tech,
    evidence: (tech.evidence || []).slice(0, MAX_EVIDENCE_PER_TECH),
    ...(tech.instances
      ? {
          instances: tech.instances.map((inst) => ({
            ...inst,
            evidence: (inst.evidence || []).slice(0, MAX_EVIDENCE_PER_TECH),
          })),
        }
      : {}),
  }));

  let candidate: InspectionReport = {
    ...masked,
    technologies: trimmedTechnologies,
  };

  if (estimateJsonByteSize(candidate) <= maxSingleReportBytes) {
    return candidate;
  }

  // 単一レポートの上限を超える場合は evidence 文字列長と付随リストを段階的に縮小する
  const compactEvidence = (ev: Evidence): Evidence => ({
    ...ev,
    value: ev.value.slice(0, 160),
    source: ev.source.slice(0, 160),
    ...(ev.detail ? { detail: ev.detail.slice(0, 160) } : {}),
  });

  candidate = {
    ...candidate,
    technologies: candidate.technologies.map((tech) => ({
      ...tech,
      evidence: tech.evidence.slice(0, 5).map(compactEvidence),
      ...(tech.instances
        ? {
            instances: tech.instances.map((inst) => ({
              ...inst,
              evidence: inst.evidence.slice(0, 5).map(compactEvidence),
            })),
          }
        : {}),
    })),
    mixedContent: (candidate.mixedContent || []).slice(0, 50),
    ...(candidate.externalConnections
      ? {
          externalConnections: {
            ...candidate.externalConnections,
            connections: (candidate.externalConnections.connections || [])
              .slice(0, 50)
              .map((c) => ({
                ...c,
                sampleUrls: (c.sampleUrls || []).slice(0, 3),
              })),
          },
        }
      : {}),
  };

  if (estimateJsonByteSize(candidate) <= maxSingleReportBytes) {
    return candidate;
  }

  // それでも超える場合は最小限の evidence (1件) に切り詰める
  return {
    ...candidate,
    technologies: candidate.technologies.map((tech) => ({
      ...tech,
      evidence: tech.evidence.slice(0, 1).map(compactEvidence),
      ...(tech.instances
        ? {
            instances: tech.instances.map((inst) => ({
              ...inst,
              evidence: inst.evidence.slice(0, 1).map(compactEvidence),
            })),
          }
        : {}),
    })),
    mixedContent: [],
  };
}

/**
 * 調査レポートを履歴に保存する (v1.7.0 T10 / IMPL-06, IMPL-07)
 * - URL のクエリ・フラグメントを除去
 * - evidence を 1 技術あたり 20 件までに切り詰め、単一レポートのサイズ上限を適用
 * - 直列化キューで同時書き込み時のロストアップデートを防止
 * - 合計サイズが 8 MB を超える場合は古い履歴から削除
 *
 * @param report 調査レポート
 * @param maxEntries 保持する最大件数
 * @param maxTotalBytes 履歴全体の最大バイト数（デフォルト: 8 MB）
 */
export async function saveReportToHistory(
  report: InspectionReport,
  maxEntries = DEFAULT_MAX_HISTORY,
  maxTotalBytes = MAX_TOTAL_HISTORY_BYTES
): Promise<void> {
  return runSerializedHistoryMutation(async () => {
    const preparedReport = enforceReportStorageLimits(report);
    const history = await getAllHistoryReports();
    // 既存の同一IDがあれば先頭に更新し、最大件数に切り詰める
    const updated = [
      preparedReport,
      ...history.filter((h) => h.id !== preparedReport.id),
    ].slice(0, maxEntries);

    // 合計サイズが上限（8 MB）を超える場合は古いもの（末尾）から削除する
    while (updated.length > 1 && estimateJsonByteSize(updated) > maxTotalBytes) {
      updated.pop();
    }

    await chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: updated });
  });
}

/**
 * 保存されているすべての調査レポートを取得する
 */
export async function getAllHistoryReports(): Promise<InspectionReport[]> {
  const data = await chrome.storage.local.get(STORAGE_KEY_HISTORY);
  const rawReports = (data[STORAGE_KEY_HISTORY] as InspectionReport[]) || [];
  return rawReports.map((r) => sanitizeReportUrls(r));
}

/**
 * 履歴一覧用のサマリーリストを取得する
 */
export async function getHistorySummaries(): Promise<HistoryEntrySummary[]> {
  const reports = await getAllHistoryReports();
  return reports.map((r) => ({
    id: r.id,
    url: stripUrlQueryAndFragment(r.url),
    hostname: r.hostname,
    inspectedAt: r.inspectedAt,
    technologyCount: r.technologies.length,
    requiresAttentionCount: r.summary.requiresAttentionCount,
    isHttps: r.summary.isHttps,
  }));
}

/**
 * 指定したIDの調査レポートを取得する
 */
export async function getReportById(id: string): Promise<InspectionReport | null> {
  const reports = await getAllHistoryReports();
  return reports.find((r) => r.id === id) || null;
}

/**
 * 指定したIDの履歴を削除する
 */
export async function deleteReportById(id: string): Promise<void> {
  return runSerializedHistoryMutation(async () => {
    const reports = await getAllHistoryReports();
    const filtered = reports.filter((r) => r.id !== id);
    await chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: filtered });
  });
}

/**
 * すべての調査履歴をクリアする
 */
export async function clearAllHistory(): Promise<void> {
  return runSerializedHistoryMutation(async () => {
    await chrome.storage.local.remove(STORAGE_KEY_HISTORY);
  });
}

export { compareReportsEnhanced } from './diff';
import { compareReportsEnhanced } from './diff';

/**
 * 2つの調査結果レポートを比較する（差分比較Diff）
 */
export interface ReportComparison {
  reportA: InspectionReport;
  reportB: InspectionReport;
  addedTechnologies: string[];
  removedTechnologies: string[];
  versionChanges: Array<{ technology: string; before: string | null; after: string | null }>;
  newSecurityIssues: string[];
  resolvedSecurityIssues: string[];
}

export function compareReports(
  reportA: InspectionReport, // 古い方
  reportB: InspectionReport  // 新しい方
): ReportComparison {
  return compareReportsEnhanced(reportA, reportB);
}
