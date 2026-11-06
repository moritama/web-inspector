#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * レポート整合性チェッカー (scripts/report-lint.mjs) - v1.7.1 T03
 *
 * 診断レポート（JSON と Markdown の組）を機械的に検査し、件数・ステータス表示・
 * 推奨対応ロードマップ・通信先・項目名・コードスパン・検出根拠・完全性の整合性を検証します。
 *
 * 検査項目:
 *   (1) R01: 要確認と内訳の一致
 *   (2) R02: 表のステータスと JSON の status の一致
 *   (3) R03: ロードマップの各行に対応する指摘がある
 *   (4) R04: 根拠のホストが通信先に含まれ、通信先に alternate や form の送信先だけのホストがない（T05 以降に有効化）
 *   (5) R05: 同じ項目名が status で変わらない
 *   (6) R06: コードスパン内に \ がない
 *   (7) R07: 同じ根拠が重複しない
 *   (8) R08: 完全性が「完全」なら通信先が 1 件以上（T05・T06 以降に有効化）
 *
 * 使い方:
 *   npm run reports:lint
 *   node scripts/report-lint.mjs [ディレクトリまたはJSONファイル...]
 *   node scripts/report-lint.mjs --include-pending
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const DEFAULT_FIXTURES_DIR = path.join(ROOT_DIR, 'tests', 'fixtures', 'reports');

/**
 * 検査項目の定義一覧
 * 後続タスク（T05・T06）で有効化する項目は pending: true に設定している。
 */
export const CHECK_DEFINITIONS = [
  {
    id: 'R01',
    number: 1,
    title: '要確認と内訳の一致',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R02',
    number: 2,
    title: '表のステータスと JSON の status の一致',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R03',
    number: 3,
    title: 'ロードマップの各行に対応する指摘がある',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R04',
    number: 4,
    title: '根拠のホストが通信先に含まれ、通信先に alternate や form の送信先だけのホストがない',
    pending: true,
    pendingUntil: 'T05',
  },
  {
    id: 'R05',
    number: 5,
    title: '同じ項目名が status で変わらない',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R06',
    number: 6,
    title: 'コードスパン内に \\ がない',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R07',
    number: 7,
    title: '同じ根拠が重複しない',
    pending: false,
    pendingUntil: null,
  },
  {
    id: 'R08',
    number: 8,
    title: '完全性が「完全」なら通信先が 1 件以上',
    pending: true,
    pendingUntil: 'T05/T06',
  },
];

/**
 * 固定診断項目の checkId プレフィックスに対する正規の項目名マップ
 */
export const CANONICAL_SECURITY_CHECK_NAMES = [
  { prefix: 'SEC-XFO-', expectedName: 'X-Frame-Options' },
  { prefix: 'SEC-HSTS-', expectedName: 'HSTS (Strict-Transport-Security)' },
  { prefix: 'SEC-XCTO-', expectedName: 'X-Content-Type-Options' },
  { prefix: 'SEC-REF-', expectedName: 'Referrer-Policy' },
  { prefix: 'SEC-PERM-', expectedName: 'Permissions-Policy' },
  { prefix: 'SEC-HTTPS-', expectedName: 'HTTPS暗号化通信' },
  { prefix: 'SEC-CORS-', expectedName: 'CORS (Cross-Origin Resource Sharing)' },
];

/**
 * 現在保留中（pending）の検査項目定義リストを返す
 */
export function getPendingChecks(options = {}) {
  if (options.includePending) return [];
  if (options.pendingIds) {
    const set = new Set(options.pendingIds);
    return CHECK_DEFINITIONS.filter((c) => set.has(c.id));
  }
  return CHECK_DEFINITIONS.filter((c) => c.pending);
}

/**
 * セキュリティ診断項目が許容・除外設定によって除外されているか判定する
 */
function isExcludedByException(check) {
  return (
    check?.exceptionStatus === 'accepted' ||
    check?.exceptionStatus === 'false-positive' ||
    check?.exceptionStatus === 'muted'
  );
}

/**
 * セキュリティ診断項目が「要確認」に該当するか判定する
 */
function isRequiresAttention(check) {
  const isIssue = check?.status === 'warning' || check?.status === 'fail';
  return isIssue && !isExcludedByException(check);
}

/**
 * JSON の status から期待される Markdown 表のステータス表記を返す
 */
function expectedMarkdownStatusBadge(status) {
  switch (status) {
    case 'pass':
      return 'PASS';
    case 'info':
      return 'INFO';
    case 'warning':
      return '**WARN**';
    case 'fail':
      return '**FAIL**';
    case 'unknown':
      return 'UNKNOWN';
    default:
      return String(status ?? '').toUpperCase();
  }
}

/**
 * Markdown 文字列から指定した見出し（## N. ...）のセクション本文を抽出する
 */
function extractMarkdownSection(markdown, headingPrefix) {
  const lines = String(markdown ?? '').split(/\r?\n/);
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim().startsWith(headingPrefix)) {
      startIdx = i + 1;
      break;
    }
  }
  if (startIdx === -1) return null;

  const sectionLines = [];
  for (let i = startIdx; i < lines.length; i++) {
    if (/^##\s+\d+\./.test(lines[i].trim())) {
      break;
    }
    sectionLines.push(lines[i]);
  }
  return sectionLines.join('\n');
}

/**
 * Markdown 表の 1 行をセル配列に分割する（エスケープされた \| は分割しない）
 */
function splitMarkdownTableRow(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith('|') || !trimmed.endsWith('|')) return null;
  const inner = trimmed.slice(1, -1);
  const cells = [];
  let current = '';
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '\\' && i + 1 < inner.length && inner[i + 1] === '|') {
      current += '\\|';
      i++;
    } else if (inner[i] === '|') {
      cells.push(current.trim());
      current = '';
    } else {
      current += inner[i];
    }
  }
  cells.push(current.trim());
  return cells;
}

/**
 * 表セル内の \| エスケープを元に戻す
 */
function unescapeTableCell(text) {
  return String(text ?? '').replace(/\\\|/g, '|').trim();
}

/**
 * URL 文字列からホスト名（小文字）を抽出する（相対 URL 等は null）
 */
function extractHostnameFromUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!/^https?:\/\//i.test(trimmed)) return null;
  try {
    return new URL(trimmed).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * (1) R01: 要確認と内訳の一致
 */
export function checkAttentionAndSeverityBreakdown(report, markdown) {
  const violations = [];
  const checks = Array.isArray(report?.securityChecks) ? report.securityChecks : [];
  const attentionChecks = checks.filter(isRequiresAttention);

  const expected = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const c of attentionChecks) {
    const sev = String(c.severity || '').toLowerCase();
    if (sev === 'critical') expected.critical++;
    else if (sev === 'high') expected.high++;
    else if (sev === 'medium') expected.medium++;
    else expected.low++;
  }
  for (const c of checks) {
    if (c.status === 'pass' || c.status === 'info') expected.info++;
    else if (c.status === 'unknown') expected.unknown++;
  }

  const actualAttention = report?.summary?.requiresAttentionCount;
  const sf = report?.summary?.securityFindings || {};
  const sfCritical = sf.critical ?? 0;
  const sfHigh = sf.high ?? 0;
  const sfMedium = sf.medium ?? 0;
  const sfLow = sf.low ?? 0;
  const sfInfo = sf.info ?? 0;
  const sfSum = sfCritical + sfHigh + sfMedium + sfLow;

  if (actualAttention !== attentionChecks.length) {
    violations.push(
      `JSONの requiresAttentionCount (${actualAttention}) が要確認項目の実数 (${attentionChecks.length}) と一致しません`
    );
  }
  if (sfSum !== actualAttention) {
    violations.push(
      `JSONの重大度内訳 CRITICAL〜LOW の合計 (${sfSum}) が requiresAttentionCount (${actualAttention}) と一致しません`
    );
  }
  if (
    sfCritical !== expected.critical ||
    sfHigh !== expected.high ||
    sfMedium !== expected.medium ||
    sfLow !== expected.low
  ) {
    violations.push(
      `JSONの重大度内訳 (C:${sfCritical}/H:${sfHigh}/M:${sfMedium}/L:${sfLow}) が要確認項目の内訳 (C:${expected.critical}/H:${expected.high}/M:${expected.medium}/L:${expected.low}) と一致しません`
    );
  }
  if (sfInfo !== expected.info) {
    violations.push(
      `JSONの securityFindings.info (${sfInfo}) が pass/info 項目の件数 (${expected.info}) と一致しません`
    );
  }

  if (typeof markdown === 'string' && markdown.trim().length > 0) {
    const sec1 = extractMarkdownSection(markdown, '## 1.');
    const attMatch = sec1 ? sec1.match(/\|\s*要確認項目数\s*\|\s*\*\*(\d+)\s*件\*\*\s*\|/) : null;
    if (!attMatch) {
      violations.push('Markdownの「1. 調査概要」に「要確認項目数」の行が見つかりません');
    } else {
      const mdAttention = Number(attMatch[1]);
      if (mdAttention !== actualAttention) {
        violations.push(
          `Markdownの要確認項目数 (${mdAttention}) が JSON の requiresAttentionCount (${actualAttention}) と一致しません`
        );
      }

      const sec3 = extractMarkdownSection(markdown, '## 3.');
      if (!sec3) {
        violations.push('Markdownの「3. 調査結果サマリー」セクションが見つかりません');
      } else {
        const parseSevCount = (label) => {
          const re = new RegExp(`\\|\\s*\\*\\*${label}[^|]*\\*\\*\\s*\\|\\s*\\*\\*(\\d+)\\*\\*\\s*\\|`);
          const m = sec3.match(re);
          return m ? Number(m[1]) : null;
        };
        const mdCrit = parseSevCount('CRITICAL');
        const mdHigh = parseSevCount('HIGH');
        const mdMed = parseSevCount('MEDIUM');
        const mdLow = parseSevCount('LOW');
        const mdInfo = parseSevCount('INFO');

        if (mdCrit === null || mdHigh === null || mdMed === null || mdLow === null || mdInfo === null) {
          violations.push('Markdownの「セキュリティ指摘レベル内訳」表から重大度別の件数を読み取れません');
        } else {
          const mdSum = mdCrit + mdHigh + mdMed + mdLow;
          if (mdSum !== mdAttention) {
            violations.push(
              `Markdownの CRITICAL〜LOW の合計 (${mdSum}) が要確認項目数 (${mdAttention}) と一致しません`
            );
          }
          if (
            mdCrit !== sfCritical ||
            mdHigh !== sfHigh ||
            mdMed !== sfMedium ||
            mdLow !== sfLow ||
            mdInfo !== sfInfo
          ) {
            violations.push(
              `Markdownの重大度内訳 (C:${mdCrit}/H:${mdHigh}/M:${mdMed}/L:${mdLow}/I:${mdInfo}) が JSON (C:${sfCritical}/H:${sfHigh}/M:${sfMedium}/L:${sfLow}/I:${sfInfo}) と一致しません`
            );
          }
        }
      }
    }
  }

  return violations;
}

/**
 * (2) R02: 表のステータスと JSON の status の一致
 */
export function checkTableStatusMatchesJson(report, markdown) {
  const violations = [];
  const checks = Array.isArray(report?.securityChecks) ? report.securityChecks : [];
  const sec5 = extractMarkdownSection(markdown, '## 5.');

  if (sec5 === null) {
    violations.push('Markdownの「5. セキュリティ診断結果」セクションが見つかりません');
    return violations;
  }

  const lines = sec5
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('|') && l.endsWith('|'));

  // ヘッダー行と区切り行を除外
  const dataRows = lines
    .map(splitMarkdownTableRow)
    .filter(
      (cells) =>
        cells &&
        cells.length >= 2 &&
        cells[0] !== '診断項目' &&
        !cells.every((c) => /^:?-{2,}:?$/.test(c))
    );

  if (checks.length === 0) {
    if (dataRows.length !== 1 || dataRows[0][0] !== 'なし') {
      violations.push('securityChecks が 0 件ですが、Markdown表が「| なし |」になっていません');
    }
    return violations;
  }

  if (dataRows.length !== checks.length) {
    violations.push(
      `Markdownのセキュリティ診断結果表の行数 (${dataRows.length}) が JSON の securityChecks 件数 (${checks.length}) と一致しません`
    );
  }

  const count = Math.min(dataRows.length, checks.length);
  for (let i = 0; i < count; i++) {
    const check = checks[i];
    const row = dataRows[i];
    const expectedBadge = expectedMarkdownStatusBadge(check.status);
    const actualBadge = row[1];

    if (actualBadge !== expectedBadge) {
      violations.push(
        `診断項目 "${check.name}" (${check.checkId}) の JSON status は "${check.status}" ですが、Markdown表のステータスが "${actualBadge}" になっています（期待値: "${expectedBadge}"）`
      );
    }

    const expectedSev = String(check.severity || '').toUpperCase();
    const actualSev = row[2];
    if (actualSev !== expectedSev) {
      violations.push(
        `診断項目 "${check.name}" (${check.checkId}) の JSON severity は "${expectedSev}" ですが、Markdown表の重大度が "${actualSev}" になっています`
      );
    }
  }

  return violations;
}

/**
 * (3) R03: ロードマップの各行に対応する指摘がある
 */
export function checkRoadmapMatchesFindings(report, markdown) {
  const violations = [];
  const checks = Array.isArray(report?.securityChecks) ? report.securityChecks : [];
  const attentionChecks = checks.filter(isRequiresAttention);
  const sec13 = extractMarkdownSection(markdown, '## 13.');

  if (sec13 === null) {
    violations.push('Markdownの「13. 推奨対応ロードマップ」セクションが見つかりません');
    return violations;
  }

  const lines = sec13.split(/\r?\n/);
  const bulletLines = lines.filter((l) => /^\s*-\s+/.test(l));

  if (attentionChecks.length === 0) {
    if (bulletLines.length > 0) {
      violations.push(
        `要確認の指摘が 0 件ですが、ロードマップに ${bulletLines.length} 件の項目行が出力されています`
      );
    }
    if (!sec13.includes('対応が必要な項目はありません')) {
      violations.push(
        '要確認の指摘が 0 件ですが、ロードマップに「対応が必要な項目はありません」が出力されていません'
      );
    }
    return violations;
  }

  if (sec13.includes('対応が必要な項目はありません')) {
    violations.push(
      `要確認の指摘が ${attentionChecks.length} 件ありますが、ロードマップが「対応が必要な項目はありません」になっています`
    );
  }

  if (bulletLines.length === 0) {
    violations.push(
      `要確認の指摘が ${attentionChecks.length} 件ありますが、ロードマップに箇条書き項目がありません`
    );
    return violations;
  }

  const attentionByName = new Map();
  for (const c of attentionChecks) {
    const nameKey = String(c.name || '').trim();
    if (!attentionByName.has(nameKey)) {
      attentionByName.set(nameKey, []);
    }
    attentionByName.get(nameKey).push(c);
  }

  const matchedCheckIndices = new Set();
  let currentGroup = null;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (/^\d+\.\s+\*\*至急対応/.test(trimmed)) {
      currentGroup = 'urgent';
      continue;
    }
    if (/^\d+\.\s+\*\*計画的対応/.test(trimmed)) {
      currentGroup = 'planned';
      continue;
    }
    if (/^\d+\.\s+\*\*継続的改善/.test(trimmed)) {
      currentGroup = 'low';
      continue;
    }

    if (/^\s*-\s+/.test(rawLine)) {
      const m = rawLine.match(/^\s*-\s+\*\*(.+?)\*\*\s*:\s*(.+)$/);
      if (!m) {
        violations.push(`ロードマップの項目行が「- **<指摘名>**: <推奨対応>」の形式ではありません: "${trimmed}"`);
        continue;
      }

      const itemName = unescapeTableCell(m[1]);
      const candidates = attentionByName.get(itemName);
      if (!candidates || candidates.length === 0) {
        violations.push(
          `ロードマップの項目 "${itemName}" に対応する要確認の指摘が securityChecks に存在しません`
        );
        continue;
      }

      // まだマッチしていない候補を優先して選ぶ
      let matched = candidates.find((c) => !matchedCheckIndices.has(c));
      if (!matched) matched = candidates[0];
      matchedCheckIndices.add(matched);

      const sev = String(matched.severity || '').toLowerCase();
      if (currentGroup === 'urgent' && sev !== 'critical' && sev !== 'high') {
        violations.push(
          `ロードマップの「至急対応 (CRITICAL / HIGH)」に重大度 "${sev}" の指摘 "${itemName}" が含まれています`
        );
      } else if (currentGroup === 'planned' && sev !== 'medium') {
        violations.push(
          `ロードマップの「計画的対応 (MEDIUM)」に重大度 "${sev}" の指摘 "${itemName}" が含まれています`
        );
      } else if (currentGroup === 'low' && (sev === 'critical' || sev === 'high' || sev === 'medium')) {
        violations.push(
          `ロードマップの「継続的改善 (LOW)」に重大度 "${sev}" の指摘 "${itemName}" が含まれています`
        );
      }
    }
  }

  for (const c of attentionChecks) {
    if (!matchedCheckIndices.has(c)) {
      violations.push(`要確認の指摘 "${c.name}" (${c.checkId}) がロードマップに出力されていません`);
    }
  }

  return violations;
}

/**
 * (4) R04: 根拠のホストが通信先に含まれ、通信先に alternate や form の送信先だけのホストがない
 */
export function checkConnectionsMatchEvidence(report) {
  const violations = [];
  const connections = Array.isArray(report?.externalConnections?.connections)
    ? report.externalConnections.connections
    : [];
  const connHosts = new Set(
    connections.map((c) => String(c.hostname || '').toLowerCase()).filter(Boolean)
  );

  const technologies = Array.isArray(report?.technologies) ? report.technologies : [];
  const networkEvidenceTypes = new Set(['script-url', 'css-url', 'css-comment', 'response-header']);
  const nonConnRelPattern = /\b(alternate|canonical|hreflang|dns-prefetch|preconnect|form)\b/i;

  const validResourceHosts = new Set();
  const pageHost = String(report?.hostname || '').toLowerCase() || extractHostnameFromUrl(report?.url);
  if (pageHost) validResourceHosts.add(pageHost);

  const nonConnectionRefHosts = new Set();

  // 1. 技術の根拠 (evidence) を走査
  const allEvidences = [];
  for (const tech of technologies) {
    if (Array.isArray(tech.evidence)) {
      for (const ev of tech.evidence) {
        allEvidences.push({ techName: tech.technology, ev });
      }
    }
    if (Array.isArray(tech.instances)) {
      for (const inst of tech.instances) {
        if (Array.isArray(inst.evidence)) {
          for (const ev of inst.evidence) {
            allEvidences.push({ techName: tech.technology, ev });
          }
        }
      }
    }
  }

  for (const { techName, ev } of allEvidences) {
    if (!ev || typeof ev !== 'object') continue;
    const descriptor = `${ev.name || ''} ${ev.detail || ''}`;
    const isNonConnRef = ev.type === 'link' || nonConnRelPattern.test(descriptor);

    const valueHost = extractHostnameFromUrl(ev.value);
    const sourceHost = extractHostnameFromUrl(ev.source);
    const targetHost = valueHost || sourceHost;

    if (isNonConnRef) {
      if (targetHost) nonConnectionRefHosts.add(targetHost);
      continue;
    }

    if (networkEvidenceTypes.has(ev.type) && targetHost) {
      validResourceHosts.add(targetHost);
      if (!connHosts.has(targetHost)) {
        violations.push(
          `技術 "${techName}" の根拠 (${ev.type}: ${ev.value || ev.source}) のホスト "${targetHost}" が通信先 (externalConnections) に含まれていません`
        );
      }
    }
  }

  // 2. mixedContent の走査 (form は送信先であり読み込みリソースではない)
  const mixedContent = Array.isArray(report?.mixedContent) ? report.mixedContent : [];
  for (const item of mixedContent) {
    const h = extractHostnameFromUrl(item?.url);
    if (!h) continue;
    if (item.resourceType === 'form') {
      nonConnectionRefHosts.add(h);
    } else {
      validResourceHosts.add(h);
    }
  }

  // 3. 補助フィールド (referenceOnlyHosts 等がレポートに記録されている場合)
  if (Array.isArray(report?.referenceOnlyHosts)) {
    for (const h of report.referenceOnlyHosts) {
      if (typeof h === 'string' && h.trim()) {
        nonConnectionRefHosts.add(h.trim().toLowerCase());
      }
    }
  }

  // 4. 通信先に alternate や form の送信先だけのホストが含まれていないか確認
  for (const conn of connections) {
    const h = String(conn?.hostname || '').toLowerCase();
    if (!h) continue;

    if (conn.onlyReference === true || conn.sourceType === 'alternate' || conn.sourceType === 'form') {
      violations.push(
        `通信先に参照のみ (${conn.sourceType || 'reference'}) のホスト "${h}" が含まれています`
      );
      continue;
    }

    const sampleUrls = Array.isArray(conn?.sampleUrls) ? conn.sampleUrls : [];
    const hasOnlyNonConnSamples =
      sampleUrls.length > 0 &&
      sampleUrls.every((u) => /[?&](hreflang|alternate|form)=/i.test(String(u)) || /^form:/i.test(String(u)));

    if (hasOnlyNonConnSamples) {
      violations.push(`通信先に alternate または form のみのホスト "${h}" が含まれています`);
      continue;
    }

    if (nonConnectionRefHosts.has(h) && !validResourceHosts.has(h)) {
      violations.push(
        `通信先に alternate または form の送信先だけのホスト "${h}" が含まれています`
      );
    }
  }

  return violations;
}

/**
 * (5) R05: 同じ項目名が status で変わらない
 */
export function checkConsistentCheckNames(report, markdown) {
  const violations = [];
  const checks = Array.isArray(report?.securityChecks) ? report.securityChecks : [];

  const seenFixedCheckNames = new Map();

  for (const c of checks) {
    const checkId = String(c?.checkId || '');
    const name = String(c?.name || '');

    for (const rule of CANONICAL_SECURITY_CHECK_NAMES) {
      if (checkId.startsWith(rule.prefix) && name !== rule.expectedName) {
        violations.push(
          `診断項目 ${checkId} (status: ${c.status}) の項目名が "${name}" になっています（status によらず "${rule.expectedName}" に統一する必要があります）`
        );
      }
    }

    // 固定 checkId が同一レポート内で異なる name を持っていないか確認
    const isDynamicLibraryCheck =
      checkId.startsWith('SEC-EOL-') ||
      checkId.startsWith('SEC-CVE-') ||
      checkId.startsWith('SEC-MISMATCH-');
    if (checkId && !isDynamicLibraryCheck) {
      if (seenFixedCheckNames.has(checkId) && seenFixedCheckNames.get(checkId) !== name) {
        violations.push(
          `同一 checkId "${checkId}" に対して異なる項目名 ("${seenFixedCheckNames.get(checkId)}" と "${name}") が使われています`
        );
      }
      seenFixedCheckNames.set(checkId, name);
    }
  }

  // Markdown セクション 5 の表の項目名とも一致しているか確認
  if (typeof markdown === 'string' && markdown.trim().length > 0 && checks.length > 0) {
    const sec5 = extractMarkdownSection(markdown, '## 5.');
    if (sec5) {
      const dataRows = sec5
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.startsWith('|') && l.endsWith('|'))
        .map(splitMarkdownTableRow)
        .filter(
          (cells) =>
            cells &&
            cells.length >= 2 &&
            cells[0] !== '診断項目' &&
            !cells.every((c) => /^:?-{2,}:?$/.test(c))
        );

      const count = Math.min(dataRows.length, checks.length);
      for (let i = 0; i < count; i++) {
        const mdName = unescapeTableCell(dataRows[i][0]);
        const jsonName = String(checks[i].name || '').trim();
        if (mdName !== jsonName) {
          violations.push(
            `Markdown表の診断項目名 "${mdName}" が JSON の name "${jsonName}" (${checks[i].checkId}) と一致しません`
          );
        }
      }
    }
  }

  return violations;
}

/**
 * (6) R06: コードスパン内に \ がない
 */
export function checkNoBackslashInCodeSpans(markdown) {
  const violations = [];
  if (typeof markdown !== 'string' || !markdown) return violations;

  // フェンスドコードブロック (``` ... ```) を行数を保ったまま空行に置き換える
  const stripped = markdown.replace(/^```[\s\S]*?^```/gm, (block) =>
    '\n'.repeat(block.split(/\r?\n/).length - 1)
  );

  const lines = stripped.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const regex = /(`+)([^`]+?)\1/g;
    let m;
    while ((m = regex.exec(line)) !== null) {
      const codeContent = m[2];
      if (codeContent.includes('\\')) {
        violations.push(
          `行 ${i + 1} のコードスパン ${m[0]} 内にバックスラッシュ (\\) が含まれています`
        );
      }
    }
  }

  return violations;
}

/**
 * (7) R07: 同じ根拠が重複しない
 */
export function checkNoDuplicateEvidence(report, markdown) {
  const violations = [];
  const technologies = Array.isArray(report?.technologies) ? report.technologies : [];

  for (const tech of technologies) {
    const checkEvidenceArray = (evList, label) => {
      if (!Array.isArray(evList)) return;
      const seen = new Set();
      for (const ev of evList) {
        if (!ev || typeof ev !== 'object') continue;
        const key = `${ev.type || ''}\0${ev.name || ''}\0${ev.value || ''}`;
        if (seen.has(key)) {
          violations.push(
            `技術 "${label}" の JSON evidence に同じ根拠が重複しています: [${ev.type}] ${ev.name}: ${ev.value}`
          );
        }
        seen.add(key);
      }
    };

    checkEvidenceArray(tech.evidence, tech.technology);
    if (Array.isArray(tech.instances)) {
      for (const inst of tech.instances) {
        checkEvidenceArray(inst.evidence, `${tech.technology} (${inst.version || '不明'})`);
      }
    }
  }

  if (typeof markdown === 'string' && markdown.trim().length > 0) {
    const sec14 = extractMarkdownSection(markdown, '## 14.');
    if (sec14) {
      let currentTechHeading = '(不明)';
      let seenLines = new Set();
      for (const rawLine of sec14.split(/\r?\n/)) {
        const trimmed = rawLine.trim();
        if (trimmed.startsWith('### ')) {
          currentTechHeading = trimmed.slice(4).trim();
          seenLines = new Set();
          continue;
        }
        if (trimmed.startsWith('- **[')) {
          if (seenLines.has(trimmed)) {
            violations.push(
              `Markdownの「14. 検出根拠」(${currentTechHeading}) に同じ根拠行が重複しています: ${trimmed}`
            );
          }
          seenLines.add(trimmed);
        }
      }
    }
  }

  return violations;
}

/**
 * (8) R08: 完全性が「完全」なら通信先が 1 件以上
 */
export function checkCompleteCoverageHasConnections(report, markdown) {
  const violations = [];
  const isComplete = report?.coverage?.overallStatus === 'complete';
  const totalConn = report?.externalConnections?.totalConnections ?? 0;
  const connLen = Array.isArray(report?.externalConnections?.connections)
    ? report.externalConnections.connections.length
    : 0;

  if (isComplete && (totalConn < 1 || connLen < 1)) {
    violations.push(
      `JSONの完全性 (coverage.overallStatus) が "complete" ですが、外部通信先が 0 件です (totalConnections: ${totalConn}, connections: ${connLen})`
    );
  }

  if (typeof markdown === 'string' && markdown.trim().length > 0) {
    const sec2 = extractMarkdownSection(markdown, '## 2.');
    const sec9 = extractMarkdownSection(markdown, '## 9.');
    if (sec2 && sec2.includes('**完全 (Complete)**') && sec9) {
      const m = sec9.match(/-\s+\*\*総通信先ホスト数:\*\*\s*(\d+)\s*件/);
      const mdTotal = m ? Number(m[1]) : 0;
      if (mdTotal < 1 || sec9.includes('外部通信先は観測されませんでした')) {
        violations.push(
          `Markdownの完全性ステータスが「完全 (Complete)」ですが、「9. 外部通信先」の総通信先ホスト数が ${mdTotal} 件です`
        );
      }
    }
  }

  return violations;
}

/**
 * 単一のレポート（JSON オブジェクトと Markdown 文字列の組）を検査する
 *
 * @param {object} report InspectionReport JSON オブジェクト
 * @param {string} markdown Markdown レポート文字列
 * @param {object} [options]
 * @param {boolean} [options.includePending=false] 保留中の検査項目も合否判定に含めるか
 * @param {string[]} [options.pendingIds] 保留扱いにする項目 ID のリスト
 */
export function lintReportPair(report, markdown, options = {}) {
  const pendingSet = new Set(getPendingChecks(options).map((c) => c.id));

  const runners = {
    R01: () => checkAttentionAndSeverityBreakdown(report, markdown),
    R02: () => checkTableStatusMatchesJson(report, markdown),
    R03: () => checkRoadmapMatchesFindings(report, markdown),
    R04: () => checkConnectionsMatchEvidence(report),
    R05: () => checkConsistentCheckNames(report, markdown),
    R06: () => checkNoBackslashInCodeSpans(markdown),
    R07: () => checkNoDuplicateEvidence(report, markdown),
    R08: () => checkCompleteCoverageHasConnections(report, markdown),
  };

  const results = [];
  const violations = [];
  const pendingViolations = [];

  for (const def of CHECK_DEFINITIONS) {
    const isPending = pendingSet.has(def.id);
    const checkViolations = runners[def.id] ? runners[def.id]() : [];
    const passed = checkViolations.length === 0;

    results.push({
      id: def.id,
      number: def.number,
      title: def.title,
      pending: isPending,
      pendingUntil: def.pendingUntil,
      passed,
      violations: checkViolations,
    });

    for (const msg of checkViolations) {
      const item = {
        id: def.id,
        number: def.number,
        title: def.title,
        pending: isPending,
        message: msg,
      };
      if (isPending) {
        pendingViolations.push(item);
      } else {
        violations.push(item);
      }
    }
  }

  const activeResults = results.filter((r) => !r.pending);
  const passedChecks = activeResults.filter((r) => r.passed).length;
  const failedChecks = activeResults.filter((r) => !r.passed).length;
  const pendingChecks = results.filter((r) => r.pending).length;

  return {
    ok: violations.length === 0,
    results,
    violations,
    pendingViolations,
    passedChecks,
    failedChecks,
    pendingChecks,
  };
}

/**
 * JSON ファイルと Markdown ファイルのペアを読み込んで検査する
 */
export function lintReportFiles(jsonPath, mdPath, options = {}) {
  if (!fs.existsSync(jsonPath)) {
    throw new Error(`レポート JSON が見つかりません: ${jsonPath}`);
  }
  if (!fs.existsSync(mdPath)) {
    throw new Error(`レポート Markdown が見つかりません: ${mdPath}`);
  }
  const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
  const markdown = fs.readFileSync(mdPath, 'utf8');
  return {
    name: path.basename(jsonPath, '.json'),
    jsonPath,
    mdPath,
    ...lintReportPair(report, markdown, options),
  };
}

/**
 * 指定ディレクトリ内のすべてのレポートペア (<name>.json と <name>.md) を検査する
 */
export function lintDirectory(dirPath, options = {}) {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`検査対象ディレクトリが見つかりません: ${dirPath}`);
  }

  const entries = fs
    .readdirSync(dirPath, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.json') && !e.name.endsWith('.snapshot.json'))
    .map((e) => e.name)
    .sort();

  const fileResults = [];
  for (const jsonFile of entries) {
    const base = jsonFile.slice(0, -'.json'.length);
    const jsonPath = path.join(dirPath, jsonFile);
    const mdPath = path.join(dirPath, `${base}.md`);
    fileResults.push(lintReportFiles(jsonPath, mdPath, options));
  }

  const pendingDefs = getPendingChecks(options);
  const passedFiles = fileResults.filter((r) => r.ok).length;
  const failedFiles = fileResults.filter((r) => !r.ok).length;

  return {
    ok: fileResults.length > 0 && failedFiles === 0,
    dirPath,
    totalFiles: fileResults.length,
    passedFiles,
    failedFiles,
    pendingCount: pendingDefs.length,
    pendingDefs,
    fileResults,
  };
}

/**
 * CLI エントリポイント
 */
export function main(argv = process.argv.slice(2)) {
  let includePending = false;
  const targets = [];

  for (const arg of argv) {
    if (arg === '--include-pending') {
      includePending = true;
    } else if (arg.startsWith('--')) {
      throw new Error(`不明なオプション: ${arg}`);
    } else {
      targets.push(arg);
    }
  }

  const options = { includePending };
  const targetPaths =
    targets.length > 0
      ? targets.map((t) => path.resolve(process.cwd(), t))
      : [DEFAULT_FIXTURES_DIR];

  const allFileResults = [];
  for (const targetPath of targetPaths) {
    if (!fs.existsSync(targetPath)) {
      console.error(`[report-lint] 対象が見つかりません: ${targetPath}`);
      return 1;
    }
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      const dirRes = lintDirectory(targetPath, options);
      allFileResults.push(...dirRes.fileResults);
    } else if (targetPath.endsWith('.json') || targetPath.endsWith('.md')) {
      const base = targetPath.replace(/\.(json|md)$/, '');
      allFileResults.push(lintReportFiles(`${base}.json`, `${base}.md`, options));
    } else {
      console.error(`[report-lint] サポートされないファイル形式です: ${targetPath}`);
      return 1;
    }
  }

  if (allFileResults.length === 0) {
    console.error('[report-lint] 検査対象のレポート（.json / .md）が 0 件です。');
    return 1;
  }

  const pendingDefs = getPendingChecks(options);
  for (const res of allFileResults) {
    const relJson = path.relative(ROOT_DIR, res.jsonPath) || res.jsonPath;
    if (res.ok) {
      console.log(`  [PASS] ${relJson} (合格: ${res.passedChecks} 項目 / 保留: ${res.pendingChecks} 項目)`);
    } else {
      console.error(`  [FAIL] ${relJson}`);
      for (const v of res.violations) {
        console.error(`    - (${v.number}) [${v.id}] ${v.title}: ${v.message}`);
      }
    }
  }

  if (pendingDefs.length > 0) {
    const pendingList = pendingDefs
      .map((d) => `(${d.number}) ${d.id}: ${d.title} [${d.pendingUntil} 以降で有効化]`)
      .join(', ');
    console.log(`[report-lint] 保留中の検査項目: ${pendingList}`);
  }

  const passedFiles = allFileResults.filter((r) => r.ok).length;
  const failedFiles = allFileResults.filter((r) => !r.ok).length;
  console.log(
    `[report-lint] 検査結果: 全 ${allFileResults.length} 件 / 合格: ${passedFiles} 件 / 不合格: ${failedFiles} 件 / 保留: ${pendingDefs.length}`
  );

  return failedFiles === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    const code = main();
    process.exit(code);
  } catch (err) {
    console.error(`[report-lint] エラー: ${err?.message || err}`);
    process.exit(1);
  }
}
