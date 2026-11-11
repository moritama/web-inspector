#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * サイズ上限検証スクリプト (scripts/ci/check-size.mjs)
 *
 * build の後に実行し、同梱脆弱性 DB および dist ディレクトリのサイズが
 * G7 の上限値を超えていないかを検証する。
 * 上限の 80% を超えたら警告 (warn)、上限を超えたら失敗 (fail) とする。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** G7 サイズ上限定義 (バイト単位: 1 MiB = 1024 * 1024 バイト) */
export const SIZE_LIMITS = {
  advisoryDb: 2 * 1024 * 1024, // 2 MiB
  dist: 3 * 1024 * 1024,       // 3 MiB
};

/** 警告しきい値の比率 (80%) */
export const WARN_RATIO = 0.8;

/**
 * サイズが上限に対してどの区分に属するか判定する。
 * - bytes > limit: 'fail'
 * - bytes > limit * WARN_RATIO: 'warn'
 * - それ以外: 'ok'
 * @param {number} bytes
 * @param {number} limit
 * @returns {'ok' | 'warn' | 'fail'}
 */
export function classifySize(bytes, limit) {
  if (bytes > limit) return 'fail';
  if (bytes > limit * WARN_RATIO) return 'warn';
  return 'ok';
}

/**
 * ディレクトリ以下 (入れ子を含む) の全ファイルの合計サイズ (バイト) を計算する。
 * @param {string} dir
 * @returns {number}
 */
export function measureDirBytes(dir) {
  if (!fs.existsSync(dir)) return 0;
  let total = 0;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      total += measureDirBytes(fullPath);
    } else if (entry.isFile()) {
      total += fs.statSync(fullPath).size;
    }
  }
  return total;
}

/**
 * DB および dist ディレクトリのサイズを検証する。
 * @param {{ advisoryDbPath?: string, distDir?: string }} [options]
 * @returns {{
 *   ok: boolean,
 *   results: Array<{
 *     target: 'advisoryDb' | 'dist',
 *     path: string,
 *     bytes: number | null,
 *     limit: number,
 *     level: 'ok' | 'warn' | 'fail'
 *   }>
 * }}
 */
export function checkSizes(options = {}) {
  const advisoryDbPath = options.advisoryDbPath
    ? path.resolve(options.advisoryDbPath)
    : path.join(REPO_ROOT, 'src', 'detection', 'advisory-db.json');
  const distDir = options.distDir
    ? path.resolve(options.distDir)
    : path.join(REPO_ROOT, 'dist');

  /** @type {Array<{ target: 'advisoryDb' | 'dist', path: string, bytes: number | null, limit: number, level: 'ok' | 'warn' | 'fail' }>} */
  const results = [];

  // 1. 同梱 DB のサイズ検査
  if (fs.existsSync(advisoryDbPath) && fs.statSync(advisoryDbPath).isFile()) {
    const bytes = fs.statSync(advisoryDbPath).size;
    const level = classifySize(bytes, SIZE_LIMITS.advisoryDb);
    results.push({
      target: 'advisoryDb',
      path: advisoryDbPath,
      bytes,
      limit: SIZE_LIMITS.advisoryDb,
      level,
    });
  } else {
    results.push({
      target: 'advisoryDb',
      path: advisoryDbPath,
      bytes: null,
      limit: SIZE_LIMITS.advisoryDb,
      level: 'fail',
    });
  }

  // 2. dist ディレクトリのサイズ検査
  if (fs.existsSync(distDir) && fs.statSync(distDir).isDirectory()) {
    const bytes = measureDirBytes(distDir);
    const level = classifySize(bytes, SIZE_LIMITS.dist);
    results.push({
      target: 'dist',
      path: distDir,
      bytes,
      limit: SIZE_LIMITS.dist,
      level,
    });
  } else {
    results.push({
      target: 'dist',
      path: distDir,
      bytes: null,
      limit: SIZE_LIMITS.dist,
      level: 'fail',
    });
  }

  const ok = results.every((r) => r.level !== 'fail');
  return { ok, results };
}

/**
 * CLI コマンドライン引数をパースする
 * @param {string[]} args
 * @returns {{ advisoryDbPath?: string, distDir?: string }}
 */
function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db' && i + 1 < args.length) {
      options.advisoryDbPath = path.resolve(args[++i]);
    } else if (args[i] === '--dist' && i + 1 < args.length) {
      options.distDir = path.resolve(args[++i]);
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
  const report = checkSizes(options);

  for (const res of report.results) {
    if (res.bytes === null) {
      console.error(`::error file=${res.path}::[${res.target}] 対象ファイルまたはディレクトリが存在しません: ${res.path}`);
    } else if (res.level === 'fail') {
      console.error(
        `::error file=${res.path}::[${res.target}] サイズが上限を超えています: ${res.bytes} bytes (上限: ${res.limit} bytes)`
      );
    } else if (res.level === 'warn') {
      console.warn(
        `::warning file=${res.path}::[${res.target}] サイズが上限の80%を超えています: ${res.bytes} bytes (上限: ${res.limit} bytes)`
      );
    } else {
      console.log(`[${res.target}] OK: ${res.bytes} bytes (上限: ${res.limit} bytes)`);
    }
  }

  process.exit(report.ok ? 0 : 1);
}

if (isMainModule()) {
  main();
}
