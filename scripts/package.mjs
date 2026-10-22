/**
 * Web Technology & Security Inspector
 * Chrome Web Store 配布用ZIPパッケージ作成スクリプト (scripts/package.mjs)
 */

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();
const distDir = path.join(rootDir, 'dist');
const releaseDir = path.join(rootDir, 'release');

// package.jsonからバージョン取得
const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf-8'));
const version = pkg.version || '1.0.0';
const zipName = `web-inspector-v${version}.zip`;
const zipPath = path.join(releaseDir, zipName);

// 1. distフォルダの存在確認
if (!fs.existsSync(distDir) || !fs.existsSync(path.join(distDir, 'manifest.json'))) {
  console.error('エラー: dist フォルダまたは manifest.json が見つかりません。先に "npm run build" を実行してください。');
  process.exit(1);
}

// 2. release フォルダの作成
if (!fs.existsSync(releaseDir)) {
  fs.mkdirSync(releaseDir, { recursive: true });
}

// 既存のZIPがあれば削除（同名上書きのため）
if (fs.existsSync(zipPath)) {
  fs.unlinkSync(zipPath);
}

// 3. ZIPコマンドで dist 内部のファイルをアーカイブ化
try {
  console.log(`パッケージング中: ${zipName}...`);
  execSync(`cd "${distDir}" && zip -r "${zipPath}" . -x "*.DS_Store"`, { stdio: 'inherit' });
  
  const stats = fs.statSync(zipPath);
  const sizeKb = (stats.size / 1024).toFixed(1);
  console.log(`\n======================================================`);
  console.log(` Chrome Web Store 配布用ZIPパッケージが完成しました!`);
  console.log(` ファイル: release/${zipName} (${sizeKb} KB)`);
  console.log(`======================================================\n`);
} catch (error) {
  console.error('ZIPアーカイブの作成に失敗しました:', error);
  process.exit(1);
}
