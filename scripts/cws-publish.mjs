#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * Chrome Web Store API v2 クライアント (scripts/cws-publish.mjs)
 *
 * ※ CWS API v1.1 は 2026-10-15 でサポート終了。本スクリプトは v2 のみを使用する。
 *    https://developer.chrome.com/docs/webstore/using-api
 *
 * サブコマンド:
 *   status                               : 公開版・審査中リビジョンの状態を取得
 *   upload  --zip <path>                 : パッケージをアップロード (下書き更新)。IN_PROGRESS の場合はポーリング
 *   publish [--type STAGED_PUBLISH|DEFAULT_PUBLISH] [--deploy-percentage N] [--skip-review]
 *                                        : 審査へ提出。既定は STAGED_PUBLISH (承認後に保留し、人が公開操作)
 *
 * 認証 (いずれか):
 *   CWS_ACCESS_TOKEN                     : google-github-actions/auth (Workload Identity Federation) で発行したアクセストークン [推奨]
 *   CWS_CLIENT_ID / CWS_CLIENT_SECRET / CWS_REFRESH_TOKEN : OAuth リフレッシュトークン
 * 必須: CWS_PUBLISHER_ID, CWS_EXTENSION_ID
 */

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

const API = 'https://chromewebstore.googleapis.com';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const PUBLISH_TYPES = new Set(['STAGED_PUBLISH', 'DEFAULT_PUBLISH']);

function requireEnv(env, name) {
  const v = env[name];
  if (!v) throw new Error(`環境変数 ${name} が未設定です。`);
  return v;
}

export async function getAccessToken(env, fetchImpl = fetch) {
  if (env.CWS_ACCESS_TOKEN) return env.CWS_ACCESS_TOKEN;
  const body = new URLSearchParams({
    client_id: requireEnv(env, 'CWS_CLIENT_ID'),
    client_secret: requireEnv(env, 'CWS_CLIENT_SECRET'),
    refresh_token: requireEnv(env, 'CWS_REFRESH_TOKEN'),
    grant_type: 'refresh_token',
  });
  const res = await fetchImpl(TOKEN_URL, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) throw new Error(`アクセストークン取得に失敗しました (HTTP ${res.status}): ${json.error || ''}`);
  return json.access_token;
}

async function call(fetchImpl, token, method, url, { body, contentType } = {}) {
  const res = await fetchImpl(url, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(contentType ? { 'Content-Type': contentType } : {}) },
    body,
  });
  const text = await res.text();
  let json;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { raw: text.slice(0, 500) };
  }
  if (!res.ok) {
    const msg = json?.error?.message || json.raw || text.slice(0, 300);
    throw new Error(`CWS API エラー ${method} ${url} (HTTP ${res.status}): ${msg}`);
  }
  return json;
}

export function createClient({ env = process.env, fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), log = console.log } = {}) {
  const publisher = requireEnv(env, 'CWS_PUBLISHER_ID');
  const item = requireEnv(env, 'CWS_EXTENSION_ID');
  const name = `publishers/${encodeURIComponent(publisher)}/items/${encodeURIComponent(item)}`;
  let tokenPromise;
  const token = () => (tokenPromise ||= getAccessToken(env, fetchImpl));

  return {
    async status() {
      return call(fetchImpl, await token(), 'GET', `${API}/v2/${name}:fetchStatus`);
    },
    async upload(zipPath, { pollIntervalMs = 5000, maxPolls = 60 } = {}) {
      const data = fs.readFileSync(zipPath);
      let res = await call(fetchImpl, await token(), 'POST', `${API}/upload/v2/${name}:upload`, { body: data, contentType: 'application/zip' });
      let state = res.uploadState;
      for (let i = 0; i < maxPolls && (state === 'IN_PROGRESS' || state === 'UPLOAD_IN_PROGRESS'); i++) {
        log(`  アップロード処理中... (${i + 1}/${maxPolls})`);
        await sleep(pollIntervalMs);
        const st = await this.status();
        state = st.lastAsyncUploadState || st.uploadState || state;
        res = { ...res, uploadState: state };
      }
      if (state !== 'SUCCEEDED') throw new Error(`アップロードが完了しませんでした (uploadState=${state})`);
      return res;
    },
    async publish({ publishType = 'STAGED_PUBLISH', deployPercentage, skipReview = false } = {}) {
      if (!PUBLISH_TYPES.has(publishType)) throw new Error(`不正な publishType: ${publishType}`);
      const body = { publishType, skipReview, blockOnWarnings: true };
      if (deployPercentage !== undefined) {
        const p = Number(deployPercentage);
        if (!Number.isInteger(p) || p < 0 || p > 100) throw new Error(`deployPercentage は 0〜100 の整数: ${deployPercentage}`);
        body.deployInfos = [{ deployPercentage: p }];
      }
      return call(fetchImpl, await token(), 'POST', `${API}/v2/${name}:publish`, { body: JSON.stringify(body), contentType: 'application/json' });
    },
  };
}

function parseArgs(argv) {
  const [cmd, ...rest] = argv.slice(2);
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--zip') opts.zip = rest[++i];
    else if (rest[i] === '--type') opts.publishType = rest[++i];
    else if (rest[i] === '--deploy-percentage') opts.deployPercentage = rest[++i];
    else if (rest[i] === '--skip-review') opts.skipReview = true;
  }
  return { cmd, opts };
}

async function main() {
  const { cmd, opts } = parseArgs(process.argv);
  const client = createClient();
  let result;
  if (cmd === 'status') result = await client.status();
  else if (cmd === 'upload') {
    if (!opts.zip || !fs.existsSync(opts.zip)) throw new Error(`--zip に存在するファイルを指定してください: ${opts.zip}`);
    result = await client.upload(opts.zip);
  } else if (cmd === 'publish') result = await client.publish(opts);
  else throw new Error('使い方: cws-publish.mjs <status|upload|publish> [options]');
  // トークン等は出力しない。レスポンスのみ表示
  console.log(JSON.stringify(result, null, 2));
  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Chrome Web Store: ${cmd}\n\n\`\`\`json\n${JSON.stringify(result, null, 2)}\n\`\`\`\n`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error(`[cws] ${err.message}`);
    process.exit(1);
  });
}
