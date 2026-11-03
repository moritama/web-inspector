#!/usr/bin/env node
/**
 * Chrome Web Store API の status 応答を検査し、
 * 審査却下（REJECTED）や公開停止（SUSPENDED / TAKEN_DOWN 等）の状態を検出した際に
 * GitHub Issue の作成またはコメント追記を行うための判定スクリプト。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createClient } from '../cws-publish.mjs';

/** アラート（Issue 起票・コメント）対象となる異常ステータス一覧 */
export const ALERT_STATES = new Set([
  'REJECTED',
  'SUSPENDED',
  'TAKEN_DOWN',
  'REMOVED',
  'DISABLED',
  'BLOCKED',
  'FAILURE'
]);

/** 起票する Issue のデフォルトタイトル */
export const DEFAULT_ISSUE_TITLE = 'Chrome Web Store status alert: review rejected or item suspended';

/**
 * CWS_ENABLED の値が有効（'true' または true）かどうかを判定する。
 * @param {unknown} value CWS_ENABLED の値
 * @returns {boolean}
 */
export function isCwsEnabled(value) {
  return value === true || value === 'true';
}

/**
 * fetchStatus のレスポンスから、異常状態（却下・停止など）を抽出する。
 * Chrome Web Store API v2 の fetchStatus 応答形式（submittedItemRevisionStatus / publishedItemRevisionStatus）と
 * 単体テスト・将来拡張用のトップレベル state / status の両方に対応する。
 *
 * @param {Record<string, unknown>} statusResponse CWS status の JSON オブジェクト
 * @returns {{
 *   isAlert: boolean,
 *   submittedState: string | null,
 *   publishedState: string | null,
 *   topLevelState: string | null,
 *   alertReasons: string[]
 * }}
 */
export function inspectStatusPayload(statusResponse) {
  if (!statusResponse || typeof statusResponse !== 'object') {
    return {
      isAlert: true,
      submittedState: null,
      publishedState: null,
      topLevelState: null,
      alertReasons: ['Empty or invalid status response']
    };
  }

  const submittedState =
    typeof statusResponse.submittedItemRevisionStatus?.state === 'string'
      ? statusResponse.submittedItemRevisionStatus.state.toUpperCase()
      : null;

  const publishedState =
    typeof statusResponse.publishedItemRevisionStatus?.state === 'string'
      ? statusResponse.publishedItemRevisionStatus.state.toUpperCase()
      : null;

  const rawTop =
    typeof statusResponse.state === 'string'
      ? statusResponse.state
      : typeof statusResponse.status === 'string'
        ? statusResponse.status
        : null;
  const topLevelState = rawTop ? rawTop.toUpperCase() : null;

  const uploadState =
    typeof statusResponse.lastAsyncUploadState === 'string'
      ? statusResponse.lastAsyncUploadState.toUpperCase()
      : null;

  const alertReasons = [];

  if (submittedState && ALERT_STATES.has(submittedState)) {
    alertReasons.push(`submittedItemRevisionStatus.state is ${submittedState}`);
  }
  if (publishedState && ALERT_STATES.has(publishedState)) {
    alertReasons.push(`publishedItemRevisionStatus.state is ${publishedState}`);
  }
  if (topLevelState && ALERT_STATES.has(topLevelState)) {
    alertReasons.push(`status state is ${topLevelState}`);
  }
  if (uploadState && ALERT_STATES.has(uploadState)) {
    alertReasons.push(`lastAsyncUploadState is ${uploadState}`);
  }
  if (statusResponse.takenDown === true) {
    alertReasons.push('item is marked as takenDown');
  }
  if (statusResponse.warned === true) {
    alertReasons.push('item has an active policy warning (warned=true)');
  }

  return {
    isAlert: alertReasons.length > 0,
    submittedState,
    publishedState,
    topLevelState,
    alertReasons
  };
}

/**
 * Chrome Web Store の状態と環境設定を評価し、Issue 作成・コメント要否を決定する。
 *
 * @param {Record<string, unknown> | null} statusResponse CWS status の応答オブジェクト
 * @param {object} [options={}] オプション
 * @param {boolean|string} [options.cwsEnabled=true] CWS_ENABLED の値（'true' / true のときのみ動作）
 * @param {number|string|null} [options.existingIssueNumber=null] 既存のオープン Issue 番号（あればコメント追記）
 * @param {string} [options.runUrl=''] GitHub Actions の実行 URL
 * @returns {{
 *   enabled: boolean,
 *   skipped: boolean,
 *   isAlert: boolean,
 *   action: 'skip' | 'none' | 'create' | 'comment',
 *   shouldCreateIssue: boolean,
 *   shouldCommentIssue: boolean,
 *   existingIssueNumber: number | string | null,
 *   submittedState: string | null,
 *   publishedState: string | null,
 *   topLevelState: string | null,
 *   alertReasons: string[],
 *   issueTitle: string,
 *   issueBody: string
 * }}
 */
export function evaluateCwsStatus(statusResponse, options = {}) {
  const {
    cwsEnabled = true,
    existingIssueNumber = null,
    runUrl = ''
  } = options;

  const enabled = isCwsEnabled(cwsEnabled);
  if (!enabled) {
    return {
      enabled: false,
      skipped: true,
      isAlert: false,
      action: 'skip',
      shouldCreateIssue: false,
      shouldCommentIssue: false,
      existingIssueNumber: null,
      submittedState: null,
      publishedState: null,
      topLevelState: null,
      alertReasons: [],
      issueTitle: DEFAULT_ISSUE_TITLE,
      issueBody: ''
    };
  }

  const inspected = inspectStatusPayload(statusResponse);
  const normalizedIssue =
    existingIssueNumber !== null &&
    existingIssueNumber !== undefined &&
    String(existingIssueNumber).trim() !== ''
      ? existingIssueNumber
      : null;

  if (!inspected.isAlert) {
    return {
      enabled: true,
      skipped: false,
      isAlert: false,
      action: 'none',
      shouldCreateIssue: false,
      shouldCommentIssue: false,
      existingIssueNumber: normalizedIssue,
      submittedState: inspected.submittedState,
      publishedState: inspected.publishedState,
      topLevelState: inspected.topLevelState,
      alertReasons: [],
      issueTitle: DEFAULT_ISSUE_TITLE,
      issueBody: ''
    };
  }

  const shouldCommentIssue = normalizedIssue !== null;
  const shouldCreateIssue = !shouldCommentIssue;
  const action = shouldCommentIssue ? 'comment' : 'create';

  const bodyLines = [
    '## Chrome Web Store 審査・公開ステータスの異常を検出しました',
    '',
    '定期ステータス確認（`cws-status`）において、Chrome Web Store アイテムの却下または停止状態を検出しました。',
    '',
    '### 検出理由',
    ...inspected.alertReasons.map((r) => `- \`${r}\``),
    '',
    '### レスポンス内容',
    '```json',
    JSON.stringify(statusResponse, null, 2),
    '```',
    '',
    '### 対応手順',
    '1. Chrome Web Store Developer Dashboard の「ステータス」画面および通知メールで却下・停止の理由を確認してください。',
    '2. 脆弱性 DB の自動更新に起因する場合は、`docs/MAINTENANCE_GUIDE.md` の手順に従い `ADVISORY_AUTO_MERGE` と `CWS_AUTO_PUBLISH` を `false` に設定して自動パイプラインを一時停止してください。',
    '3. 問題を修正した新しいバージョンを提出し、審査が通過したらこの Issue をクローズしてください。'
  ];

  if (runUrl) {
    bodyLines.push('', `Workflow Run: ${runUrl}`);
  }

  return {
    enabled: true,
    skipped: false,
    isAlert: true,
    action,
    shouldCreateIssue,
    shouldCommentIssue,
    existingIssueNumber: normalizedIssue,
    submittedState: inspected.submittedState,
    publishedState: inspected.publishedState,
    topLevelState: inspected.topLevelState,
    alertReasons: inspected.alertReasons,
    issueTitle: DEFAULT_ISSUE_TITLE,
    issueBody: bodyLines.join('\n')
  };
}

/**
 * CWS_ENABLED の確認からステータス取得・判定・（任意の）Issue 起票クライアント呼び出しまでを一括実行する。
 *
 * @param {object} [params={}] 実行パラメータ
 * @param {Record<string, string|undefined>} [params.env=process.env] 環境変数オブジェクト
 * @param {{ status: () => Promise<Record<string, unknown>> }} [params.client] CWS クライアント（DI 用）
 * @param {typeof fetch} [params.fetchImpl] fetch 実装（DI 用）
 * @param {() => Promise<Record<string, unknown>> | Record<string, unknown>} [params.getStatus] ステータス取得関数（DI 用）
 * @param {Record<string, unknown>} [params.statusResponse] 事前取得済みのステータス応答
 * @param {number|string|null} [params.existingIssueNumber=null] 既存 Issue 番号
 * @param {{ createIssue?: (args: { title: string, body: string }) => Promise<unknown>, commentIssue?: (args: { issueNumber: number|string, body: string }) => Promise<unknown> }} [params.issueClient] Issue 操作クライアント（DI 用）
 * @param {string} [params.runUrl=''] ワークフロー実行 URL
 */
export async function runCwsStatusCheck(params = {}) {
  const {
    env = process.env,
    client,
    fetchImpl,
    getStatus,
    statusResponse: providedResponse,
    existingIssueNumber = null,
    issueClient,
    runUrl = ''
  } = params;

  const cwsEnabled = env.CWS_ENABLED;
  if (!isCwsEnabled(cwsEnabled)) {
    return evaluateCwsStatus(null, { cwsEnabled: false, existingIssueNumber, runUrl });
  }

  let statusResponse = providedResponse;
  if (!statusResponse) {
    if (typeof getStatus === 'function') {
      statusResponse = await getStatus();
    } else if (client && typeof client.status === 'function') {
      statusResponse = await client.status();
    } else {
      const cwsClient = createClient({ env, fetchImpl });
      statusResponse = await cwsClient.status();
    }
  }

  const evaluation = evaluateCwsStatus(statusResponse, {
    cwsEnabled: true,
    existingIssueNumber,
    runUrl
  });

  if (evaluation.shouldCreateIssue && issueClient && typeof issueClient.createIssue === 'function') {
    await issueClient.createIssue({
      title: evaluation.issueTitle,
      body: evaluation.issueBody
    });
  } else if (
    evaluation.shouldCommentIssue &&
    issueClient &&
    typeof issueClient.commentIssue === 'function'
  ) {
    await issueClient.commentIssue({
      issueNumber: evaluation.existingIssueNumber,
      body: evaluation.issueBody
    });
  }

  return {
    ...evaluation,
    statusResponse
  };
}

/**
 * コマンドライン引数を解析する。
 * @param {string[]} argv 引数配列
 * @returns {Record<string, string>}
 */
function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        args[key] = next;
        i++;
      } else {
        args[key] = 'true';
      }
    }
  }
  return args;
}

/**
 * CLI エントリポイント。
 */
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const statusFile = args['status-file'];
  const existingIssue = args['existing-issue'] || process.env.EXISTING_ISSUE_NUMBER || '';
  const outBody = args['out-body'];
  const outJson = args['out-json'];
  const runUrl = args['run-url'] || process.env.WORKFLOW_RUN_URL || '';

  let providedResponse;
  if (statusFile) {
    providedResponse = JSON.parse(fs.readFileSync(path.resolve(statusFile), 'utf8'));
  }

  const result = await runCwsStatusCheck({
    env: {
      ...process.env,
      CWS_ENABLED: args['cws-enabled'] ?? process.env.CWS_ENABLED ?? 'true'
    },
    statusResponse: providedResponse,
    existingIssueNumber: existingIssue || null,
    runUrl
  });

  if (outBody && result.issueBody) {
    fs.writeFileSync(path.resolve(outBody), result.issueBody, 'utf8');
  }
  if (outJson) {
    fs.writeFileSync(path.resolve(outJson), `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  }

  if (process.env.GITHUB_OUTPUT) {
    const lines = [
      `enabled=${result.enabled}`,
      `skipped=${result.skipped}`,
      `is_alert=${result.isAlert}`,
      `action=${result.action}`,
      `should_create_issue=${result.shouldCreateIssue}`,
      `should_comment_issue=${result.shouldCommentIssue}`,
      `issue_title=${result.issueTitle}`
    ];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, 'utf8');
  }

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`[cws-status] ERROR: ${err.message}`);
    process.exit(1);
  });
}
