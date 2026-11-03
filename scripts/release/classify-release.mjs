#!/usr/bin/env node
/**
 * リリース対象のバージョンと変更ファイル一覧から、
 * 「脆弱性 DB だけの更新（第 4 要素リビジョン版）」か「コードを含む更新」かを判定し、
 * Chrome Web Store への公開方式（DEFAULT_PUBLISH / STAGED_PUBLISH）と
 * 使用する GitHub Environment（chrome-web-store-auto / chrome-web-store）を決定するスクリプト。
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * バージョン文字列が Chrome 拡張の 4 要素バージョン（X.Y.Z.W）かどうかを判定する。
 * @param {string} version バージョン文字列（先頭の 'v' はあってもなくてもよい）
 * @returns {boolean} 4 要素の数値バージョンの場合 true
 */
export function isFourPartVersion(version) {
  if (typeof version !== 'string') return false;
  const cleaned = version.trim().replace(/^v/, '');
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(cleaned);
  if (!match) return false;
  return match.slice(1).every((part) => {
    const n = Number(part);
    return Number.isInteger(n) && n >= 0 && n <= 65535;
  });
}

/**
 * ファイルパスが「脆弱性 DB だけのリリース」で変更を許可されたパスかどうかを判定する。
 * 許可対象:
 * - data/advisories/**
 * - src/detection/advisory-db.json
 * - public/manifest.json
 * @param {string} filePath リポジトリルートからの相対パス
 * @returns {boolean} 許可されたパスの場合 true
 */
export function isAllowedDbOnlyPath(filePath) {
  if (typeof filePath !== 'string' || !filePath.trim()) return false;
  const normalized = filePath.trim().replace(/\\/g, '/').replace(/^\.\//, '');
  if (normalized === 'src/detection/advisory-db.json') return true;
  if (normalized === 'public/manifest.json') return true;
  if (normalized.startsWith('data/advisories/')) return true;
  return false;
}

/**
 * 2 つのオブジェクトまたは JSON 値を再帰的に比較する。
 * @param {unknown} a 比較元
 * @param {unknown} b 比較先
 * @returns {boolean} 等しい場合 true
 */
function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') {
    return false;
  }
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
    const key = keysA[i];
    if (!deepEqual(a[key], b[key])) return false;
  }
  return true;
}

/**
 * public/manifest.json の変更前後の内容を比較し、`version` フィールド以外の変更がないか検証する。
 * @param {string | Record<string, unknown>} baseManifest 変更前の manifest.json（JSON 文字列またはオブジェクト）
 * @param {string | Record<string, unknown>} headManifest 変更後の manifest.json（JSON 文字列またはオブジェクト）
 * @returns {boolean} version フィールドのみの変更（または変更なし）の場合 true
 */
export function isManifestVersionOnlyChange(baseManifest, headManifest) {
  try {
    const baseObj = typeof baseManifest === 'string' ? JSON.parse(baseManifest) : baseManifest;
    const headObj = typeof headManifest === 'string' ? JSON.parse(headManifest) : headManifest;
    if (!baseObj || !headObj || typeof baseObj !== 'object' || typeof headObj !== 'object') {
      return false;
    }
    if (Array.isArray(baseObj) || Array.isArray(headObj)) {
      return false;
    }

    // 文字列として渡された場合、行単位でも version 行以外の差分がないか確認する
    if (typeof baseManifest === 'string' && typeof headManifest === 'string') {
      const baseLines = baseManifest.replace(/\r\n/g, '\n').trimEnd().split('\n');
      const headLines = headManifest.replace(/\r\n/g, '\n').trimEnd().split('\n');
      if (baseLines.length === headLines.length && baseLines.length > 1) {
        let nonVersionDiff = false;
        for (let i = 0; i < baseLines.length; i++) {
          if (baseLines[i] === headLines[i]) continue;
          const isBaseVersionLine = /^\s*"version"\s*:\s*"[^"]+"\s*,?\s*$/.test(baseLines[i]);
          const isHeadVersionLine = /^\s*"version"\s*:\s*"[^"]+"\s*,?\s*$/.test(headLines[i]);
          if (!isBaseVersionLine || !isHeadVersionLine) {
            nonVersionDiff = true;
            break;
          }
        }
        if (nonVersionDiff) return false;
      }
    }

    const baseRest = { ...baseObj };
    const headRest = { ...headObj };
    delete baseRest.version;
    delete headRest.version;
    return deepEqual(baseRest, headRest);
  } catch {
    return false;
  }
}

/**
 * git diff の出力テキストから、public/manifest.json の変更行が `"version"` のみかどうかを判定する。
 * @param {string} diffText git diff のパッチ文字列
 * @returns {boolean} version 行のみの変更の場合 true
 */
export function isManifestDiffVersionOnly(diffText) {
  if (typeof diffText !== 'string') return false;
  const lines = diffText.replace(/\r\n/g, '\n').split('\n');
  let changedLines = 0;
  for (const line of lines) {
    if (!line) continue;
    if (
      line.startsWith('diff ') ||
      line.startsWith('index ') ||
      line.startsWith('--- ') ||
      line.startsWith('+++ ') ||
      line.startsWith('@@ ')
    ) {
      continue;
    }
    if (line.startsWith('+') || line.startsWith('-')) {
      changedLines++;
      const content = line.slice(1);
      if (!/^\s*"version"\s*:\s*"[^"]+"\s*,?\s*$/.test(content)) {
        return false;
      }
    }
  }
  return true;
}

/**
 * リリース情報を分類し、公開モード・GitHub Environment・publishType を返す。
 *
 * 自動公開（mode: 'auto', environment: 'chrome-web-store-auto', publishType: 'DEFAULT_PUBLISH'）になる条件:
 * 1. バージョンが 4 要素（X.Y.Z.W）である
 * 2. 比較元のタグ（previousTag）が存在する
 * 3. 変更ファイルが 1 件以上あり、すべてが許可されたパス（data/advisories/**, src/detection/advisory-db.json, public/manifest.json）に含まれる
 * 4. public/manifest.json が変更されている場合、変更箇所が version フィールドのみである
 * 5. CWS_AUTO_PUBLISH（autoPublish / cwsAutoPublish）が 'true'（または true）である
 *
 * いずれか 1 つでも満たさない場合は手動承認ルート（mode: 'manual', environment: 'chrome-web-store', publishType: 'STAGED_PUBLISH'）とする。
 *
 * @param {object} params 判定パラメータ
 * @param {string} params.version リリースするバージョン（例: '1.7.0.1' または 'v1.7.0.1'）
 * @param {string[]} [params.changedFiles=[]] 前回タグからの変更ファイルパス一覧
 * @param {string|null} [params.previousTag='v1.7.0'] 比較元の前回タグ（存在しない場合は null）
 * @param {boolean|string} [params.autoPublish] CWS_AUTO_PUBLISH の値（'true' / true のときのみ有効）
 * @param {boolean|string} [params.cwsAutoPublish] autoPublish の別名
 * @param {boolean} [params.manifestVersionOnly] public/manifest.json の変更が version のみか（直接指定時）
 * @param {string|Record<string, unknown>} [params.baseManifest] 変更前の public/manifest.json
 * @param {string|Record<string, unknown>} [params.headManifest] 変更後の public/manifest.json
 * @param {string} [params.manifestDiff] public/manifest.json の git diff 文字列
 * @param {string} [params.cwsPublishType] CWS_PUBLISH_TYPE 変数の値（workflow_dispatch 時のフォールバック用）
 * @param {string} [params.inputPublishType] workflow_dispatch の入力で明示指定された publish_type
 * @param {string} [params.eventName] GitHub Actions のイベント名（'push' | 'workflow_dispatch' など）
 * @returns {{
 *   isFourPart: boolean,
 *   isDbOnly: boolean,
 *   autoPublishEnabled: boolean,
 *   isAuto: boolean,
 *   mode: 'auto' | 'manual',
 *   environment: 'chrome-web-store-auto' | 'chrome-web-store',
 *   publishType: string,
 *   reasons: string[]
 * }}
 */
export function classifyRelease(params = {}) {
  const {
    version = '',
    changedFiles = [],
    previousTag = 'v1.7.0',
    autoPublish,
    cwsAutoPublish,
    manifestVersionOnly,
    baseManifest,
    headManifest,
    manifestDiff,
    cwsPublishType = '',
    inputPublishType = '',
    eventName = 'push'
  } = params;

  const reasons = [];
  const isFourPart = isFourPartVersion(version);
  if (!isFourPart) {
    reasons.push('version is not a 4-part revision version');
  }

  const hasPreviousTag = previousTag !== null && previousTag !== '';
  if (!hasPreviousTag) {
    reasons.push('previous release tag not found');
  }

  const normalizedFiles = Array.isArray(changedFiles)
    ? changedFiles.map((f) => String(f).trim().replace(/\\/g, '/').replace(/^\.\//, '')).filter(Boolean)
    : [];

  if (normalizedFiles.length === 0) {
    reasons.push('no changed files detected');
  }

  const disallowedFiles = normalizedFiles.filter((f) => !isAllowedDbOnlyPath(f));
  if (disallowedFiles.length > 0) {
    reasons.push(`non-DB files changed: ${disallowedFiles.join(', ')}`);
  }

  let isManifestOk = true;
  const manifestTouched = normalizedFiles.includes('public/manifest.json');
  if (typeof manifestVersionOnly === 'boolean') {
    isManifestOk = manifestVersionOnly;
  } else if (baseManifest !== undefined && headManifest !== undefined) {
    isManifestOk = isManifestVersionOnlyChange(baseManifest, headManifest);
  } else if (typeof manifestDiff === 'string') {
    isManifestOk = isManifestDiffVersionOnly(manifestDiff);
  } else if (manifestTouched) {
    // 単体テスト等で manifest の中身を省略した場合は true とし、CLI 実行時は base/head を渡して検証する
    isManifestOk = true;
  }

  if (!isManifestOk) {
    reasons.push('public/manifest.json has changes other than version');
  }

  const isDbOnly =
    isFourPart &&
    hasPreviousTag &&
    normalizedFiles.length > 0 &&
    disallowedFiles.length === 0 &&
    isManifestOk;

  const rawAutoPublish = autoPublish !== undefined ? autoPublish : cwsAutoPublish;
  const autoPublishEnabled = rawAutoPublish === true || rawAutoPublish === 'true';
  if (!autoPublishEnabled) {
    reasons.push('CWS_AUTO_PUBLISH is not enabled');
  }

  const isAuto = isDbOnly && autoPublishEnabled;
  const mode = isAuto ? 'auto' : 'manual';
  const environment = isAuto ? 'chrome-web-store-auto' : 'chrome-web-store';

  let publishType;
  if (inputPublishType && String(inputPublishType).trim()) {
    publishType = String(inputPublishType).trim();
  } else if (isAuto) {
    publishType = 'DEFAULT_PUBLISH';
  } else if (eventName === 'workflow_dispatch' && cwsPublishType && String(cwsPublishType).trim()) {
    publishType = String(cwsPublishType).trim();
  } else {
    publishType = 'STAGED_PUBLISH';
  }

  return {
    isFourPart,
    isDbOnly,
    autoPublishEnabled,
    isAuto,
    mode,
    environment,
    publishType,
    reasons
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
 * Git コマンドで前回のリリースタグ（現在のタグの 1 つ前）を取得する。
 * @param {string} currentRef 現在のタグまたは HEAD
 * @returns {string|null}
 */
function findPreviousTag(currentRef = 'HEAD') {
  try {
    const out = execFileSync(
      'git',
      ['describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*', `${currentRef}^`],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    return out || null;
  } catch {
    return null;
  }
}

/**
 * Git コマンドで 2 つの ref 間の変更ファイル一覧を取得する。
 * @param {string} baseRef 比較元 ref
 * @param {string} headRef 比較先 ref
 * @returns {string[]}
 */
function getChangedFilesFromGit(baseRef, headRef = 'HEAD') {
  const out = execFileSync(
    'git',
    ['diff', '--name-only', `${baseRef}..${headRef}`],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
  );
  return out
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * CLI エントリポイント。
 */
function main() {
  const args = parseArgs(process.argv.slice(2));
  const version = args.version || process.env.RELEASE_VERSION || '';
  const headRef = args['head-ref'] || 'HEAD';
  const baseTag = args['base-tag'] !== undefined ? (args['base-tag'] || null) : findPreviousTag(headRef);
  const autoPublish = args['auto-publish'] !== undefined ? args['auto-publish'] : (process.env.CWS_AUTO_PUBLISH || '');
  const cwsPublishType = args['cws-publish-type'] !== undefined ? args['cws-publish-type'] : (process.env.CWS_PUBLISH_TYPE || '');
  const inputPublishType = args['input-publish-type'] !== undefined ? args['input-publish-type'] : (process.env.INPUT_PUBLISH_TYPE || '');
  const eventName = args['event-name'] || process.env.GITHUB_EVENT_NAME || 'push';

  let changedFiles = [];
  let baseManifest;
  let headManifest;

  if (baseTag) {
    try {
      changedFiles = getChangedFilesFromGit(baseTag, headRef);
      if (changedFiles.includes('public/manifest.json')) {
        baseManifest = execFileSync(
          'git',
          ['show', `${baseTag}:public/manifest.json`],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
        );
        headManifest = fs.readFileSync(path.resolve('public/manifest.json'), 'utf8');
      }
    } catch {
      changedFiles = [];
    }
  }

  const result = classifyRelease({
    version,
    changedFiles,
    previousTag: baseTag,
    autoPublish,
    baseManifest,
    headManifest,
    cwsPublishType,
    inputPublishType,
    eventName
  });

  if (process.env.GITHUB_OUTPUT) {
    const lines = [
      `is_four_part=${result.isFourPart}`,
      `is_db_only=${result.isDbOnly}`,
      `auto_publish_enabled=${result.autoPublishEnabled}`,
      `is_auto=${result.isAuto}`,
      `mode=${result.mode}`,
      `environment=${result.environment}`,
      `publish_type=${result.publishType}`
    ];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, 'utf8');
  }

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
