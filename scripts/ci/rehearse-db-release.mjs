#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * DB更新リリース予行スクリプト (scripts/ci/rehearse-db-release.mjs)
 *
 * 作業ツリーの一時コピーを作成し、
 * 1. bump-db-revision.mjs を実行して manifest の第4要素 (DBリビジョン) を採番
 * 2. advisory-db.json の dataVersion を進め、integrity を再計算
 * 3. 一時コピー内でテスト (既定: npm test) を実行
 * することで、DB更新リリース時のテスト破損を未然に検出する。
 * 元の作業ツリーは一切変更しない。
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

/** 既定のテスト実行コマンド */
export const DEFAULT_TEST_COMMAND = ['npm', 'test'];

/** コピーから除外するディレクトリ・ファイル名のセット */
const EXCLUDED_NAMES = new Set(['.git', 'node_modules', 'dist', 'reports']);

/**
 * dataVersion (YYYYMMDD 形式) を進めた値を返す (UTC暦で翌日)。
 * YYYYMMDD (数字8桁かつ暦として妥当) でない値の場合は例外を投げる。
 * @param {string} current
 * @returns {string}
 */
export function nextDataVersion(current) {
  if (typeof current !== 'string' || !/^\d{8}$/.test(current)) {
    throw new Error(`dataVersion の形式が不正です (YYYYMMDD 形式の8桁の数字が必要です): ${current}`);
  }
  const y = Number(current.slice(0, 4));
  const m = Number(current.slice(4, 6));
  const d = Number(current.slice(6, 8));

  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) {
    throw new Error(`dataVersion が有効な日付ではありません: ${current}`);
  }

  dt.setUTCDate(dt.getUTCDate() + 1);

  const nextY = dt.getUTCFullYear();
  const nextM = String(dt.getUTCMonth() + 1).padStart(2, '0');
  const nextD = String(dt.getUTCDate()).padStart(2, '0');
  return `${nextY}${nextM}${nextD}`;
}

/**
 * DB オブジェクトを複製し、dataVersion を翌日に進め、
 * integrity を libraries の sha256 で再計算した新しいオブジェクトを返す。
 * 元のオブジェクトは変更しない。
 * @param {Record<string, unknown>} db
 * @returns {Record<string, unknown>}
 */
export function bumpAdvisoryDb(db) {
  if (!db || typeof db !== 'object') {
    throw new Error('db オブジェクトが不正です');
  }
  const cloned = structuredClone(db);
  const nextVer = nextDataVersion(/** @type {string} */ (cloned.dataVersion));
  const librariesStr = JSON.stringify(cloned.libraries);
  const digest = crypto.createHash('sha256').update(librariesStr).digest('hex');

  cloned.dataVersion = nextVer;
  cloned.integrity = {
    algorithm: 'sha256',
    target: 'libraries',
    digest,
  };

  return cloned;
}

/**
 * ディレクトリを再帰走査して、除外対象以外のファイルをコピーする
 * @param {string} src
 * @param {string} dst
 */
function copyTreeRecursively(src, dst) {
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    if (EXCLUDED_NAMES.has(entry.name)) continue;

    const srcPath = path.join(src, entry.name);
    const dstPath = path.join(dst, entry.name);

    if (entry.isSymbolicLink()) {
      // シンボリックリンクはリンク先を再帰的にたどらない
      continue;
    } else if (entry.isDirectory()) {
      fs.mkdirSync(dstPath, { recursive: true });
      copyTreeRecursively(srcPath, dstPath);
    } else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}

/**
 * 作業ツリーを一時ディレクトリにコピーする
 * @param {string} sourceDir
 * @param {string} workDir
 */
function copySourceTree(sourceDir, workDir) {
  let isGit = false;
  try {
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: sourceDir,
      encoding: 'utf-8',
      stdio: 'pipe',
    }).trim();
    if (fs.realpathSync(top) === fs.realpathSync(sourceDir)) {
      isGit = true;
    }
  } catch {
    isGit = false;
  }

  if (isGit) {
    const rawFiles = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: sourceDir,
      encoding: 'utf-8',
      stdio: 'pipe',
    });
    const fileList = rawFiles.split('\0').filter(Boolean);
    for (const rel of fileList) {
      const topSegment = rel.split('/')[0];
      if (EXCLUDED_NAMES.has(topSegment)) continue;

      const srcFile = path.join(sourceDir, rel);
      const dstFile = path.join(workDir, rel);

      if (fs.existsSync(srcFile)) {
        const stat = fs.statSync(srcFile);
        if (stat.isFile()) {
          fs.mkdirSync(path.dirname(dstFile), { recursive: true });
          fs.copyFileSync(srcFile, dstFile);
        }
      }
    }
  } else {
    copyTreeRecursively(sourceDir, workDir);
  }

  // node_modules が存在すればシンボリックリンクを作成
  const srcNodeModules = path.join(sourceDir, 'node_modules');
  if (fs.existsSync(srcNodeModules)) {
    const realNodeModules = fs.realpathSync(srcNodeModules);
    fs.symlinkSync(realNodeModules, path.join(workDir, 'node_modules'), 'dir');
  }
}

/**
 * DB だけのリリースの予行を実行する。
 * @param {{
 *   sourceDir?: string,
 *   testCommand?: string[],
 *   advisoryDbPath?: string,
 *   keepWorkDir?: boolean,
 * }} [options]
 * @returns {Promise<{
 *   ok: boolean,
 *   exitCode: number | null,
 *   workDir: string,
 *   previousManifestVersion: string,
 *   manifestVersion: string,
 *   previousDataVersion: string,
 *   dataVersion: string,
 * }>}
 */
export async function rehearseDbRelease(options = {}) {
  const sourceDir = options.sourceDir ? path.resolve(options.sourceDir) : REPO_ROOT;
  const testCommand = options.testCommand ?? DEFAULT_TEST_COMMAND;
  const advisoryDbPath = options.advisoryDbPath ?? path.join('src', 'detection', 'advisory-db.json');
  const keepWorkDir = options.keepWorkDir ?? false;

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-release-rehearsal-'));

  let previousManifestVersion = '';
  let manifestVersion = '';
  let previousDataVersion = '';
  let dataVersion = '';

  try {
    // 1. 作業ツリーのコピー
    copySourceTree(sourceDir, workDir);

    // コピー前の manifest バージョンと DB dataVersion を取得
    const manifestPath = path.join(workDir, 'public', 'manifest.json');
    if (fs.existsSync(manifestPath)) {
      const manifestJson = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      previousManifestVersion = manifestJson.version ?? '';
    }

    const dbPath = path.join(workDir, advisoryDbPath);
    if (fs.existsSync(dbPath)) {
      const dbJson = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
      previousDataVersion = dbJson.dataVersion ?? '';
    }

    // 2. コピーの中の bump-db-revision.mjs を実行
    const bumpScript = path.join(workDir, 'scripts', 'advisories', 'bump-db-revision.mjs');
    if (!fs.existsSync(bumpScript)) {
      throw new Error(`bump-db-revision.mjs が見つかりません: ${bumpScript}`);
    }

    // Node.js の ESM 実行において import.meta.url と process.argv[1] を一致させるため realpathSync を使用
    const bumpScriptReal = fs.realpathSync(bumpScript);
    const childEnv = { ...process.env };
    delete childEnv.GITHUB_OUTPUT;

    const bumpProc = spawnSync(process.execPath, [bumpScriptReal], {
      cwd: workDir,
      env: childEnv,
      stdio: 'pipe',
      encoding: 'utf-8',
    });

    if (bumpProc.status !== 0) {
      return {
        ok: false,
        exitCode: bumpProc.status ?? 1,
        workDir,
        previousManifestVersion,
        manifestVersion: previousManifestVersion,
        previousDataVersion,
        dataVersion: previousDataVersion,
      };
    }

    // 更新後の manifest バージョンを取得
    if (fs.existsSync(manifestPath)) {
      const updatedManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
      manifestVersion = updatedManifest.version ?? '';
    }

    // 3. コピーの中の DB を更新
    if (!fs.existsSync(dbPath)) {
      throw new Error(`Advisory DB が見つかりません: ${dbPath}`);
    }
    const currentDb = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const bumpedDb = bumpAdvisoryDb(currentDb);
    fs.writeFileSync(dbPath, JSON.stringify(bumpedDb, null, 2) + '\n', 'utf-8');
    dataVersion = /** @type {string} */ (bumpedDb.dataVersion);

    // 4. テストコマンドを実行
    const [cmd, ...args] = testCommand;
    const testProc = spawnSync(cmd, args, {
      cwd: workDir,
      stdio: 'inherit',
      shell: process.platform === 'win32',
    });

    const exitCode = testProc.status;
    const ok = exitCode === 0;

    return {
      ok,
      exitCode,
      workDir,
      previousManifestVersion,
      manifestVersion,
      previousDataVersion,
      dataVersion,
    };
  } finally {
    if (!keepWorkDir) {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch {
        // 後始末のエラーは無視
      }
    }
  }
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
async function main() {
  console.log('DB リリース予行を開始します...');
  try {
    const report = await rehearseDbRelease();
    if (report.ok) {
      console.log(
        `予行成功: manifest ${report.previousManifestVersion} -> ${report.manifestVersion}, dataVersion ${report.previousDataVersion} -> ${report.dataVersion}`
      );
      process.exit(0);
    } else {
      console.error(`予行失敗: 終了コード ${report.exitCode}`);
      process.exit(report.exitCode ?? 1);
    }
  } catch (err) {
    console.error('予行実行中にエラーが発生しました:', err);
    process.exit(1);
  }
}

if (isMainModule()) {
  main();
}
