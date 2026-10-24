/**
 * Web Technology & Security Inspector
 * 包括的Markdown調査レポート生成モジュール (src/export/markdown.ts) - IMP-12
 * 
 * 改善仕様書 Rev.2.1（第11項）に完全準拠した15セクション構成のMarkdown報告書を生成・ダウンロードします。
 * Cookie値・機密ヘッダーは一切含めず、エビデンス保持・受動的解析の原則を堅持します。
 */

import {
  DetailedDiffItem,
  FindingException,
  InspectionReport,
} from '../shared/types';
import { compareReportsEnhanced } from '../storage/diff';

/**
 * URLから機密クエリパラメータ（token, secret, key, password等）を除去・マスクする
 */
export function sanitizeUrlForReport(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const sensitiveKeys = ['token', 'key', 'auth', 'secret', 'password', 'passwd', 'sig', 'signature', 'access_token', 'api_key'];
    for (const k of Array.from(parsed.searchParams.keys())) {
      if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
        parsed.searchParams.set(k, '***MASKED***');
      }
    }
    // 認証情報（username:password@）の除去
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Markdown特殊文字をエスケープする
 */
export function escapeMarkdown(text: string | null | undefined): string {
  if (!text) return '';
  return text
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\*/g, '\\*')
    .replace(/_/g, '\\_')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|')
    .replace(/\r\n|\n|\r/g, ' ');
}

/**
 * 調査レポートから Rev.2.1 準拠の 15セクション Markdown ドキュメントを生成する (Rev.2.1 IMP-12 / 11.3)
 *
 * @param report 今回の調査レポート
 * @param previousReport 前回の調査レポート（差分分析用・任意）
 * @param exceptions 登録された許容設定リスト（任意）
 * @returns Markdown文字列
 */
export function generateMarkdownReport(
  report: InspectionReport,
  previousReport?: InspectionReport | null,
  exceptions: FindingException[] = []
): string {
  const sanitizedUrl = sanitizeUrlForReport(report.url);
  const hostname = report.hostname;
  const inspectedDate = new Date(report.inspectedAt).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' });
  const extVer = report.extensionVersion || '1.3.3';

  // 差分分析の計算
  const diff = previousReport ? compareReportsEnhanced(previousReport, report) : null;

  const sections: string[] = [];

  // タイトル
  sections.push(`# Web Technology & Security Inspection Report\n\n**対象ホスト:** \`${hostname}\`  \n**調査実施日時:** ${inspectedDate} (JST)  \n**Inspector バージョン:** v${extVer} (Manifest V3)  \n**解析方式:** 受動的解析 (Passive Inspection) / 完全ローカル突合  \n\n---`);

  // 1. 調査概要
  sections.push(`## 1. 調査概要

| 項目 | 内容 |
|---|---|
| 対象URL | \`${sanitizedUrl}\` |
| ホスト名 | \`${hostname}\` |
| プロトコル | ${report.summary.isHttps ? 'HTTPS (暗号化通信)' : 'HTTP (非暗号化)'} |
| 診断ルールバージョン | ${escapeMarkdown(report.rulesVersion)} |
| オフライン脆弱性DBバージョン | ${escapeMarkdown(report.advisoryDatabaseVersion || '2026.10')} |
| 要確認項目数 | **${report.summary.requiresAttentionCount} 件** |
| 検出技術スタック数 | **${report.summary.totalTechnologies} 件** |
`);

  // 2. 調査範囲・完全性 (IMP-08)
  const cov = report.coverage;
  const statusLabel =
    cov?.overallStatus === 'complete'
      ? '完全 (Complete)'
      : cov?.overallStatus === 'partial'
      ? '一部制限あり (Partial)'
      : '未取得 (Unavailable)';
  sections.push(`## 2. 調査範囲・完全性 (Coverage)

- **完全性ステータス:** **${statusLabel}**
- **DOM / HTML解析:** ${cov?.dom === 'complete' ? '✅ 取得成功' : '⚠️ 一部または未取得'}
- **HTTPレスポンスヘッダー:** ${cov?.headers === 'complete' ? '✅ 取得成功' : '⚠️ 未取得 (キャッシュ/事前スキャンなし)'}
- **Cookie属性情報:** ${cov?.cookies === 'complete' ? `✅ 取得成功 (${report.cookies.length} 個観測)` : '⚠️ 権限なし/未取得'}
- **ネットワーク・通信解析:** ${cov?.network === 'complete' ? '✅ 取得成功' : '⚠️ 一部制限あり'}
${
  cov?.details?.missingPermissions && cov.details.missingPermissions.length > 0
    ? `\n> [!NOTE]\n> **未付与の権限:** ${cov.details.missingPermissions.map((s) => `\`${s}\``).join(', ')}\n`
    : ''
}
`);

  // 3. 調査結果サマリー
  sections.push(`## 3. 調査結果サマリー

### セキュリティ指摘レベル内訳
| 重大度 | 指摘件数 | 説明 |
|:---:|:---:|---|
| **HIGH (危険)** | **${report.summary.securityFindings.high}** | 直ちに対応・修正が推奨される設定不備・脆弱性 |
| **MEDIUM (警告)** | **${report.summary.securityFindings.medium}** | セキュリティ基準に抵触、またはサポート終了の技術 |
| **LOW (注意)** | **${report.summary.securityFindings.low}** | 改善が望ましい設定上の軽微な不備 |
| **INFO (情報)** | **${report.summary.securityFindings.info}** | 参考情報・セキュリティ良好な項目 |
`);

  // 4. 検出技術スタック
  sections.push(`## 4. 検出技術スタック

> [!NOTE]
> **受動的調査の原則と推定関係:** 固有シグナルから直接検出された技術と、依存関係から連動検知された技術を明確に区分しています。外部からの受動観測ではサーバー内部の実行状態を直接観測できない技術は「稼働未確認」として記録しています。

| 技術名 | カテゴリ | バージョン | 検出方式 | 連動元 / 種別 | ランタイム状態 | 確信度 | 整合性 |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
${report.technologies.length > 0 ? report.technologies.map((t) => {
  const ver = t.isCandidateGroup ? 'いずれかの可能性' : t.version ? `v${t.version}` : '不明';
  const method = t.isCandidateGroup || t.detectionMethod === 'associated' ? '候補・関連' : t.detectionMethod === 'inferred' ? '連動検知' : '直接検出';
  const relation = t.inferredFrom ? `${t.inferredFrom} (${t.implicationType || '連動'})` : '-';
  const runtime = t.runtimeStatus === 'confirmed' ? '稼働確認済' : t.runtimeStatus === 'possible' ? '稼働可能性あり' : t.runtimeStatus === 'unknown' ? '稼働未確認' : '-';
  const integrity = t.versionIntegrity?.status === 'mismatch' ? '⚠️ 不一致' : t.versionIntegrity?.status === 'match' ? '一致' : '-';
  return `| **${escapeMarkdown(t.technology)}** | ${escapeMarkdown(t.category)} | \`${escapeMarkdown(ver)}\` | ${method} | ${escapeMarkdown(relation)} | ${runtime} | ${t.confidenceLevel} (${t.confidence}%) | ${integrity} |`;
}).join('\n') : '| なし | - | - | - | - | - | - | - |'}
`);

  // 5. セキュリティ診断結果
  sections.push(`## 5. セキュリティ診断結果

| 診断項目 | ステータス | 重大度 | 観測値 | 許容状態 |
|---|:---:|:---:|---|:---:|
${report.securityChecks.length > 0 ? report.securityChecks.map((c) => {
  const statBadge = c.status === 'pass' ? 'PASS' : c.status === 'fail' ? '**FAIL**' : '**WARN**';
  const exBadge = c.exceptionStatus === 'accepted' ? '🛡️ 許容済' : c.exceptionStatus === 'false-positive' ? '❌ 誤検知除外' : '-';
  return `| ${escapeMarkdown(c.name)} | ${statBadge} | ${c.severity.toUpperCase()} | \`${escapeMarkdown(c.observed.substring(0, 60))}\` | ${exBadge} |`;
}).join('\n') : '| なし | - | - | - | - |'}
`);

  // 6. EOL・既知脆弱性情報 (IMP-06)
  sections.push(`## 6. EOL・既知脆弱性情報 (ライブラリセキュリティ)

> [!IMPORTANT]
> オフライン脆弱性DBスナップショット (Rev.2.1) とのローカル突合結果です。未登録の技術は「安全」を意味するものではありません。

| 対象技術 | バージョン | サポート状況 (EOL) | 照合ステータス | 該当CVE | 推奨対応 |
|---|:---:|:---:|:---:|---|---|
${report.technologies.map((t) => {
  const eol = t.supportStatus === 'EOL' ? `**EOL (${t.eolDate || '終了'})**` : t.supportStatus || 'Unknown';
  const matchStatus = t.offlineMatchStatus || 'Not Covered';
  const cveList = t.advisories && t.advisories.length > 0
    ? t.advisories.map((a) => `[${a.id}](https://nvd.nist.gov/vuln/detail/${a.id}) (${a.severity})`).join(', ')
    : '該当なし';
  const rec = t.advisories && t.advisories.length > 0
    ? `修正版 (v${t.advisories[0].fixedVersion || '最新'}) への更新`
    : t.supportStatus === 'EOL'
    ? '最新LTS系列への移行'
    : '現状維持';
  return `| **${escapeMarkdown(t.technology)}** | \`${escapeMarkdown(t.version || '不明')}\` | ${eol} | \`${matchStatus}\` | ${cveList} | ${rec} |`;
}).join('\n')}
`);

  // 7. Cookie属性診断 (IMP-01 / IMP-04)
  sections.push(`## 7. Cookie属性診断

※ **セキュリティ保護:** Cookieの値（Value）および認証シークレットは一切収集・出力していません。

| Cookie名 | ドメイン | パス | 用途分類 | Secure | HttpOnly | SameSite | CHIPS (Partitioned) |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
${report.cookies.length > 0 ? report.cookies.map((c) => {
  return `| \`${escapeMarkdown(c.name)}\` | \`${escapeMarkdown(c.domain || '-')}\` | \`${escapeMarkdown(c.path || '-')}\` | ${escapeMarkdown(c.category || 'general')} | ${c.secure ? 'Yes' : '**No**'} | ${c.httpOnly ? 'Yes' : '**No**'} | \`${c.sameSite || '-'}\` | ${c.partitioned ? 'Yes' : 'No'} |`;
}).join('\n') : '| なし | - | - | - | - | - | - | - |'}
`);

  // 8. CSP診断 (IMP-02 / IMP-05)
  sections.push(`## 8. CSP（Content Security Policy）診断

- **CSPポリシー保持件数:** ${report.cspPolicies?.length ?? 0} 件
${report.cspPolicies && report.cspPolicies.length > 0 ? report.cspPolicies.map((p, idx) => `
#### ポリシー #${idx + 1} [取得元: ${p.source}, モード: ${p.mode}]
\`\`\`text
${p.rawValue}
\`\`\`
`).join('\n') : '> CSPヘッダーまたはmetaタグによるCSPは設定されていません。'}
`);

  // 9. 外部通信先・サードパーティ分析 (IMP-11)
  const ext = report.externalConnections;
  sections.push(`## 9. 外部通信先・サードパーティ分析 (Public Suffix List / eTLD+1)

- **総通信先ホスト数:** ${ext?.totalConnections ?? 0} 件
- **First-Party (同一組織・自社ドメイン):** ${ext?.firstPartyCount ?? 0} 件
- **Third-Party (外部サービス通信先):** ${ext?.thirdPartyCount ?? 0} 件

| 接続先ホスト名 | 登録可能ドメイン (eTLD+1) | 所属種別 | 推定カテゴリ | 観測リソース数 |
|---|---|:---:|:---:|:---:|
${ext && ext.connections.length > 0 ? ext.connections.map((item) => {
  const partyBadge = item.partyType === 'first-party' ? 'First-Party' : item.partyType === 'third-party' ? '**Third-Party**' : 'Local';
  return `| \`${escapeMarkdown(item.hostname)}\` | \`${escapeMarkdown(item.registrableDomain)}\` | ${partyBadge} | \`${item.category}\` | ${item.resourceCount} |`;
}).join('\n') : '| 外部通信先は観測されませんでした | - | - | - | - |'}
`);

  // 10. 前回との差分 (IMP-09)
  sections.push(`## 10. 前回調査との差分 (Diff)

${diff ? `
- **前回調査日時:** ${new Date(diff.reportA.inspectedAt).toLocaleString('ja-JP')}
- **今回調査日時:** ${new Date(diff.reportB.inspectedAt).toLocaleString('ja-JP')}
- **新規検出技術:** ${diff.addedTechnologies.length > 0 ? diff.addedTechnologies.map((t) => `\`${t}\``).join(', ') : 'なし'}
- **消失技術:** ${diff.removedTechnologies.length > 0 ? diff.removedTechnologies.map((t) => `\`${t}\``).join(', ') : 'なし'}
- **新規発生した指摘:** ${diff.newSecurityIssues.length > 0 ? diff.newSecurityIssues.map((s) => `\`${s}\``).join(', ') : 'なし'}
- **解消された指摘:** ${diff.resolvedSecurityIssues.length > 0 ? diff.resolvedSecurityIssues.map((s) => `\`${s}\``).join(', ') : 'なし'}
` : '> 前回調査レポートとの比較は実行されていません（初回調査または単一レポート出力）。'}
`);

  // 11. 差分発生原因 (IMP-09)
  sections.push(`## 11. 差分発生原因の推定分析

${diff && diff.diffItems.length > 0 ? `
| 変化項目 | 差分種別 | 推定原因 | 変化内容 | 詳細解説 |
|---|:---:|:---:|---|---|
${diff.diffItems.map((item: DetailedDiffItem) => {
  return `| **${escapeMarkdown(item.target)}** | \`${item.diffType}\` | \`${item.diffCause}\` | \`${escapeMarkdown(item.before || '-')}\` &rarr; \`${escapeMarkdown(item.after || '-')}\` | ${escapeMarkdown(item.causeExplanation)} |`;
}).join('\n')}
` : '> 分析対象の有意な差分変化はありません。'}
`);

  // 12. 許容・除外設定 (IMP-10)
  sections.push(`## 12. 診断項目の許容・除外設定 (Finding Exceptions)

${exceptions.length > 0 ? `
| 状態 | 対象安定ID (FindingId) | 適用スコープ | 許容理由 | 登録日 |
|:---:|---|---|---|:---:|
${exceptions.map((ex) => {
  const stLabel = ex.status === 'accepted' ? 'リスク許容' : ex.status === 'false-positive' ? '誤検知' : '通知抑制';
  return `| **${stLabel}** | \`${escapeMarkdown(ex.findingId)}\` | \`${escapeMarkdown(ex.targetUrl || '全体適用')}\` | ${escapeMarkdown(ex.reason)} | ${ex.createdAt ? ex.createdAt.slice(0, 10) : '-'} |`;
}).join('\n')}
` : '> 現在適用されている許容・除外設定はありません。'}
`);

  // 13. 推奨対応ロードマップ
  sections.push(`## 13. 推奨対応ロードマップ

1. **至急対応 (High Severity):**
   - 既知脆弱性（CVE）が特定されたライブラリを修正済みバージョン以降へ更新する。
   - 暗号化通信（HTTPS）および混在コンテンツ（Mixed Content）の解消。
2. **計画的対応 (Medium Severity):**
   - サポート終了（EOL）を迎えたミドルウェア・ライブラリの次世代LTS系列への移行計画策定。
   - セッションCookieに対する \`Secure\`、\`HttpOnly\`、適切な \`SameSite\` 属性の付与。
   - Content-Security-Policy (CSP) の導入および \`unsafe-inline\` の排除。
3. **継続的改善 (Low / Best Practices):**
   - HSTS (\`Strict-Transport-Security\`) ヘッダーの \`max-age=31536000; includeSubDomains\` 適用。
   - 外部サードパーティスクリプトの棚卸しと整合性検証 (SRI) の導入。
`);

  // 14. 検出根拠 (エビデンス)
  sections.push(`## 14. 検出根拠 (エビデンス詳細)

${report.technologies.map((t) => `
### ${t.technology} (確信度: ${t.confidenceLevel} - ${t.confidence}%)
${t.evidence.map((e) => `- **[${e.type}]** \`${escapeMarkdown(e.name)}\`: \`${escapeMarkdown(e.value)}\` ${e.detail ? `(${escapeMarkdown(e.detail)})` : ''}`).join('\n')}
`).join('\n')}
`);

  // 15. 調査上の制限事項
  sections.push(`## 15. 調査上の制限事項・免責事項

1. **受動的解析のスコープ:**
   本拡張機能は、ブラウザが通常のWeb閲覧時に受信したHTML、CSS、JavaScript、HTTPヘッダー、Cookie属性のみを受動的に解析（Passive Inspection）しています。外部サーバーへの攻撃的なリクエスト送信や内部ソースコードの監査は行っていません。
2. **脆弱性DBの網羅性:**
   オフライン脆弱性DBに未収録のライブラリや独自フレームワークについて「脆弱性なし」と判定されていても、安全性を完全に保証するものではありません。
3. **認証後ページの扱い:**
   ログインや特定セッションを必要とする深層ページは、閲覧した範囲に限定して診断されます。
4. **機密情報の非保持:**
   Cookieの値、認証トークン、Authorizationヘッダーなどのシークレット情報はメモリ保持およびレポート出力から完全に除外されています。
`);

  return sections.join('\n\n');
}

/**
 * 生成したMarkdownレポートをブラウザからファイルとしてダウンロードする
 */
export function downloadMarkdownReport(
  report: InspectionReport,
  previousReport?: InspectionReport | null,
  exceptions: FindingException[] = []
): void {
  const content = generateMarkdownReport(report, previousReport, exceptions);
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);

  const cleanHost = report.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStr = new Date(report.inspectedAt).toISOString().slice(0, 10);
  const filename = `web-inspector-report-${cleanHost}-${dateStr}.md`;

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
