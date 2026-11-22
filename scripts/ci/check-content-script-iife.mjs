#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * content-script IIFE 検証スクリプト (scripts/ci/check-content-script-iife.mjs)
 *
 * build の後に実行し、dist/content/content-script.js が IIFE（即時実行関数式）で
 * バンドルされているかを検証する (v1.8.2 T02 / H6、指示書 §5.1)。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

/**
 * ソース文字列が IIFE に包まれているかを検証する
 * @param {string} text
 * @returns {{ ok: boolean, reason: string }}
 */
export function checkIifeSource(text) {
  // 先頭の空白・ブロックコメント・行コメントを取り除く
  const stripped = text.replace(/^(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*/, '');
  // 'use strict' または "use strict"（およびそれに続くセミコロンと空白）を取り除く
  const body = stripped.replace(/^(['"])use strict\1;?\s*/, '');

  // トップレベルの変数宣言 (const/let/class/var) または行頭の import/export があれば不合格
  if (/^(const|let|class|var)\s/.test(body) || /^(import|export)\b/m.test(body)) {
    return {
      ok: false,
      reason: '先頭がトップレベルの宣言（同じフレームへの 2 回目の注入で SyntaxError になる）',
    };
  }

  // 関数式の即時実行 ((function, (() =>, (async, !function) で始まっていなければ不合格
  if (!/^(\(\s*(function\b|\(\s*\)\s*=>|async\b)|!function\b)/.test(body)) {
    return {
      ok: false,
      reason: '先頭が IIFE に見えない',
    };
  }

  return { ok: true, reason: '' };
}

/**
 * content-script ファイルを読んで IIFE かどうかを検証する
 * @param {{ file?: string }} [options] 既定は <repo>/dist/content/content-script.js
 * @returns {{ ok: boolean, path: string, reason: string }}
 */
export function checkContentScriptIife(options = {}) {
  const filePath = options?.file
    ? path.resolve(options.file)
    : path.join(REPO_ROOT, 'dist', 'content', 'content-script.js');

  if (!fs.existsSync(filePath)) {
    return {
      ok: false,
      path: filePath,
      reason: `${filePath} が無い（npm run build の後に実行する）`,
    };
  }

  try {
    const text = fs.readFileSync(filePath, 'utf-8');
    const result = checkIifeSource(text);
    return {
      ok: result.ok,
      path: filePath,
      reason: result.reason,
    };
  } catch (e) {
    return {
      ok: false,
      path: filePath,
      reason: `ファイルの読み込みに失敗しました: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/** CLI コマンドライン引数をパースする */
function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--file' && i + 1 < args.length) {
      options.file = path.resolve(args[++i]);
    }
  }
  return options;
}

/** CLI として直接実行されたかを判定する */
function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    const scriptPath = fs.realpathSync(process.argv[1]);
    return import.meta.url === pathToFileURL(scriptPath).href;
  } catch {
    return import.meta.url === pathToFileURL(process.argv[1]).href;
  }
}

/** CLI メイン実行関数 */
function main() {
  const options = parseArgs(process.argv.slice(2));
  const res = checkContentScriptIife(options);

  if (res.ok) {
    console.log(`[content-script] OK: IIFE (${res.path})`);
    process.exit(0);
  } else {
    console.error(`::error file=${res.path}::[content-script] ${res.reason}`);
    process.exit(1);
  }
}

if (isMainModule()) {
  main();
}
