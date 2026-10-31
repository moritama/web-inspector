#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * Antigravity CLI 権限ルールの追加・削除 (scripts/dev/agy-permissions.mjs)
 *
 * docs/dev/v1.6.6/agy-permissions.json のルールを、ユーザー設定
 * ~/.gemini/antigravity-cli/settings.json の permissions.allow / permissions.deny に追記・削除する。
 * Antigravity CLI の権限設定はユーザー単位で、allow に command(*) を含むため、ほかのフォルダで agy を
 * 使うときにも効いてしまう。scripts/dev/overnight.sh は実行中だけ追加し、終了時に自動で削除する。
 * 既存の設定は残す。初回の追加時に「元から入っていたルール」を記録し、削除時はそれ以外の
 * （このキットと以前の版のキットが追加した）ルールだけを削除する。
 *
 * 使い方（リポジトリ直下で）:
 *   node scripts/dev/agy-permissions.mjs --install     # ルールを追加（初回は設定ファイルのバックアップを作成）
 *   node scripts/dev/agy-permissions.mjs --status      # 追加済みか確認（すべて入っていれば終了コード 0）
 *   node scripts/dev/agy-permissions.mjs --uninstall   # 追加したルールを削除
 *
 * 環境変数 AGY_SETTINGS で設定ファイルの場所を変更できる（テスト用）。
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEMPLATE = path.join(ROOT, 'docs', 'dev', 'v1.6.6', 'agy-permissions.json');
const SETTINGS = process.env.AGY_SETTINGS || path.join(os.homedir(), '.gemini', 'antigravity-cli', 'settings.json');
const BACKUP = `${SETTINGS}.bak-web-inspector-v166`;
const STATE = path.join(path.dirname(SETTINGS), '.web-inspector-v166-added.json');
const LISTS = ['allow', 'deny'];
const quiet = process.argv.includes('--quiet');
const log = (...a) => { if (!quiet) console.log(...a); };

/**
 * Node.js のインストール先。サンドボックスの中から node / npx を起動するには、実行ファイルと
 * そのライブラリ（Homebrew なら /opt/homebrew/opt/* の dylib など）の読み取り許可が必要になる。
 */
function nodeDir() {
  const real = fs.realpathSync(process.execPath);
  for (const p of ['/opt/homebrew', '/usr/local']) if (real.startsWith(`${p}/`)) return p;
  // nvm / volta / fnm / 公式インストーラなど: .../<version>/bin/node の <version> ディレクトリ
  return path.dirname(path.dirname(real));
}
const NODE_DIR = nodeDir();
const fill = (r) => r.split('${ROOT}').join(ROOT).split('${NODE_DIR}').join(NODE_DIR);
function loadRules() {
  const t = JSON.parse(fs.readFileSync(TEMPLATE, 'utf-8'));
  const out = { legacy: (t.legacy || []).map(fill) };
  for (const k of LISTS) out[k] = (t[k] || []).map(fill);
  return out;
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  const text = fs.readFileSync(file, 'utf-8');
  if (!text.trim()) return fallback;
  try {
    return JSON.parse(text);
  } catch (e) {
    console.error(`[NG] JSON として読めません: ${file}`);
    console.error(`     ${e.message}`);
    console.error('     コメントや末尾のカンマがあれば取り除いてから、もう一度実行してください。');
    process.exit(2);
  }
}

function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(obj, null, 2)}\n`);
}

const isConflictingAsk = (r) => r === 'command(*)' || /^command\((git|npm|npx|node)\b/.test(r);

const mode = process.argv[2];
const rules = loadRules();
const settings = readJson(SETTINGS, {});
const perms = (settings.permissions ??= {});

if (mode === '--install') {
  if (fs.existsSync(SETTINGS) && !fs.existsSync(BACKUP)) fs.copyFileSync(SETTINGS, BACKUP);
  // 元から入っていたルールを、初回だけ記録する。基準は最初の追加の前に作ったバックアップ
  // （以前の版のキットで追加済みの場合も、バックアップはその前の状態を表す）
  if (!fs.existsSync(STATE)) {
    const orig = fs.existsSync(BACKUP) ? readJson(BACKUP, {}) : {};
    const pre = {};
    for (const k of LISTS) {
      const cur = Array.isArray(orig.permissions?.[k]) ? orig.permissions[k] : [];
      pre[k] = [...new Set([...rules[k], ...rules.legacy])].filter((r) => cur.includes(r));
    }
    writeJson(STATE, { preexisting: pre });
  }
  let added = 0;
  for (const k of LISTS) {
    const cur = Array.isArray(perms[k]) ? perms[k] : [];
    for (const r of rules[k]) if (!cur.includes(r)) { cur.push(r); added++; }
    perms[k] = cur;
  }
  writeJson(SETTINGS, settings);
  log(`[OK] 権限ルールを ${added} 件追加しました: ${SETTINGS}`);
  if (fs.existsSync(BACKUP)) log(`     元の設定のバックアップ: ${BACKUP}`);
  const ask = Array.isArray(perms.ask) ? perms.ask : [];
  if (ask.some(isConflictingAsk)) {
    console.log('[注意] permissions.ask に command(*) などがあります。ask は allow より優先されるため、無人実行ではコマンドが拒否され、実行が中断します。作業中は外してください。');
  }
} else if (mode === '--uninstall') {
  const pre = readJson(STATE, { preexisting: {} }).preexisting || {};
  let removed = 0;
  for (const k of LISTS) {
    if (!Array.isArray(perms[k])) continue;
    const ours = new Set([...rules[k], ...rules.legacy]);
    const keep = new Set(pre[k] || []);
    const before = perms[k].length;
    perms[k] = perms[k].filter((r) => !ours.has(r) || keep.has(r));
    removed += before - perms[k].length;
    if (perms[k].length === 0) delete perms[k];
  }
  if (Object.keys(perms).length === 0) delete settings.permissions;
  writeJson(SETTINGS, settings);
  if (fs.existsSync(STATE)) fs.rmSync(STATE);
  log(`[OK] 権限ルールを ${removed} 件削除しました: ${SETTINGS}`);
} else if (mode === '--status') {
  const missing = [];
  for (const k of LISTS) {
    const cur = Array.isArray(perms[k]) ? perms[k] : [];
    for (const r of rules[k]) if (!cur.includes(r)) missing.push(`${k}: ${r}`);
  }
  const conflict = (Array.isArray(perms.ask) ? perms.ask : []).filter(isConflictingAsk);
  if (missing.length === 0 && conflict.length === 0) {
    log(`[OK] v1.6.6 の権限ルールがすべて入っています（${SETTINGS}）`);
    process.exit(0);
  }
  if (missing.length) console.log(`[NG] 不足しているルールが ${missing.length} 件あります（例: ${missing[0]}）。--install を実行してください。`);
  if (conflict.length) console.log(`[NG] permissions.ask の ${conflict.join(', ')} が allow より優先され、無人実行が中断します。作業中は外してください。`);
  process.exit(1);
} else {
  console.log('使い方: node scripts/dev/agy-permissions.mjs --install | --status | --uninstall');
  process.exit(2);
}
