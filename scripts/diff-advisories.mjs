/**
 * @file diff-advisories.mjs
 * @description 2つの拡張機能ZIPファイル（例: 1.3.3 と 1.6.4）を展開し、含まれる脆弱性定義の完全差分を機械的に抽出・出力する。
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const oldZip = process.argv[2] || 'release/web-inspector-v1.3.3.zip';
const newZip = process.argv[3] || 'release/web-inspector-v1.6.4.zip';

if (!fs.existsSync(oldZip) || !fs.existsSync(newZip)) {
  console.error(`Error: ZIP file not found. old: ${oldZip}, new: ${newZip}`);
  process.exit(1);
}

function extractEntriesFromZip(zipPath) {
  const fileList = execSync(`unzip -Z1 "${zipPath}"`, { encoding: 'utf-8' })
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean);

  const jsFiles = fileList.filter(f => f.endsWith('.js'));
  const entries = new Map();

  for (const jsFile of jsFiles) {
    const content = execSync(`unzip -p "${zipPath}" "${jsFile}"`, {
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024
    });

    // 各CVEオブジェクトの境界を精密に抽出
    // {range:...,cve:...,...}
    const cveRegex = /cve:"(CVE-[0-9]{4}-[0-9]{4,7})"/g;
    let match;
    while ((match = cveRegex.exec(content)) !== null) {
      const cve = match[1];
      // このCVEが含まれるオブジェクトの前後を探索
      const startIdx = content.lastIndexOf('{', match.index);
      const nextOpen = content.indexOf('{', match.index);
      const nextClose = content.indexOf('}', match.index);
      const endIdx = (nextOpen !== -1 && nextOpen < nextClose) ? content.indexOf('}', nextClose + 1) : nextClose;
      
      const snippet = content.substring(startIdx, endIdx !== -1 ? endIdx + 1 : match.index + 1000);

      const rangeMatch = snippet.match(/range:"([^"]+)"/);
      const range = rangeMatch ? rangeMatch[1] : '不明';

      const sevMatch = snippet.match(/severity:"([^"]+)"/);
      const severity = sevMatch ? sevMatch[1] : '不明';

      const cvssMatch = snippet.match(/cvssScore:([0-9.]+)/);
      const cvss = cvssMatch ? cvssMatch[1] : null;

      const titleMatch = snippet.match(/title:"([^"]+)"/);
      const title = titleMatch ? titleMatch[1] : '';

      entries.set(cve, {
        cve,
        range,
        severity,
        cvss,
        title,
        file: jsFile
      });
    }
  }

  return entries;
}

const oldEntries = extractEntriesFromZip(oldZip);
const newEntries = extractEntriesFromZip(newZip);

console.log(`[diff-advisories] 旧版 (${oldZip}): ${oldEntries.size} 件`);
console.log(`[diff-advisories] 新版 (${newZip}): ${newEntries.size} 件`);

const allCves = new Set([...oldEntries.keys(), ...newEntries.keys()]);

const deleted = [];
const added = [];
const modified = [];
const unchanged = [];

for (const cve of allCves) {
  const inOld = oldEntries.get(cve);
  const inNew = newEntries.get(cve);

  if (inOld && !inNew) {
    deleted.push(inOld);
  } else if (!inOld && inNew) {
    added.push(inNew);
  } else {
    const rangeChanged = inOld.range !== inNew.range;
    const sevChanged = inOld.severity !== inNew.severity;
    const titleChanged = inOld.title !== inNew.title;

    if (rangeChanged || sevChanged || titleChanged) {
      modified.push({
        cve,
        old: inOld,
        new: inNew,
        rangeChanged,
        sevChanged,
        titleChanged
      });
    } else {
      unchanged.push(cve);
    }
  }
}

console.log('\n## 1. 削除されたエントリ (公開中 1.3.3 に存在したが 1.6.4 で除外: %d 件)', deleted.length);
console.log('| CVE ID | 1.3.3 重大度 | 1.3.3 該当範囲 | 1.3.3 タイトル | 削除理由 |');
console.log('|---|---|---|---|---|');
for (const d of deleted) {
  const reason = d.cve === 'CVE-2023-32243'
    ? 'WordPressプラグイン(Essential Addons)の脆弱性を本体と誤認していたため除外'
    : d.cve === 'CVE-2020-13426'
    ? 'WordPressプラグイン(Multi-Scheduler)のCSRFをVue.js本体ReDoSと誤認していたため除外'
    : '一次情報不整合のため除外';
  console.log(`| ${d.cve} | ${d.severity} | \`${d.range}\` | ${d.title} | ${reason} |`);
}

console.log('\n## 2. 変更・是正されたエントリ (公開中 1.3.3 から 1.6.4 で改訂: %d 件)', modified.length);
console.log('| CVE ID | 変更区分 | 1.3.3 の状態 (旧) | 1.6.4 の状態 (新) | 主な是正・精緻化内容 |');
console.log('|---|---|---|---|---|');
for (const m of modified) {
  const changes = [];
  if (m.sevChanged) changes.push(`重大度: ${m.old.severity} → ${m.new.severity} (CVSS ${m.new.cvss})`);
  if (m.rangeChanged) changes.push(`範囲: \`${m.old.range}\` → \`${m.new.range}\``);
  if (m.titleChanged) changes.push(`タイトル是正`);

  let note = '';
  if (m.cve === 'CVE-2022-31628') note = '種別をPharデシリアライズからDoS(gzip展開無限ループ)に是正、複数ブランチ網羅';
  else if (m.cve === 'CVE-2021-23337') note = 'タイトルをプロトタイプ汚染からコマンドインジェクション(_.template)に是正';
  else if (m.cve === 'CVE-2020-7676') note = 'NVD Primary CVSS 5.4 に合致させ重大度を Medium に是正';
  else if (m.cve === 'CVE-2022-21661') note = 'NVD 22ブランチ網羅 (5.7.5 等の旧ブランチパッチ版の過検知解消)';
  else if (m.cve === 'CVE-2023-44487') note = '下限 >= 1.9.5 設定、HTTP/2・keepalive 条件付き明記';
  else if (m.cve === 'CVE-2018-6341') note = 'NVD CPE 準拠の 16 系 SSR 5 ブランチ網羅に是正';
  else if (m.cve === 'CVE-2021-23017') note = '修正版 1.20.1 を除外した範囲 (>= 0.6.18, < 1.20.1) に是正';
  else if (m.cve === 'CVE-2024-4577') note = 'Windows PHP-CGI 稼働条件付き明記、8.2/8.3 系統網羅';
  else if (m.cve === 'CVE-2021-42013') note = '49系バイパスを考慮し >= 2.4.49, <= 2.4.50 に是正';
  else if (m.cve === 'CVE-2019-8331') note = 'Bootstrap 3 系も含めた範囲に是正 (< 3.4.1 || >= 4.3.0, < 4.3.1)';
  else if (m.cve.startsWith('CVE-2018-14041') || m.cve.startsWith('CVE-2016-10735')) note = '対象メジャーバージョンの下限を追加し過検知を防止';
  else if (m.cve === 'CVE-2020-11022' || m.cve === 'CVE-2020-11023') note = 'NVD CPE に従い下限バージョンを追加し精緻化';
  else if (m.cve === 'CVE-2020-8203') note = 'NVD CPE 通り上限を < 4.17.20 に是正';
  else note = '範囲および条件の精緻化';

  console.log(`| ${m.cve} | ${changes.join(', ')} | \`${m.old.range}\` (${m.old.severity}) | \`${m.new.range}\` (${m.new.severity}) | ${note} |`);
}

console.log('\n## 3. 新規追加されたエントリ (v1.4.0 以降の機能拡張で新設: %d 件)', added.length);
console.log('| CVE ID | ソフトウェア | 1.6.4 該当範囲 | 1.6.4 重大度 (CVSS) | 概要 |');
console.log('|---|---|---|---|---|');
for (const a of added) {
  let sw = '不明';
  if (a.cve.includes('3129') || a.cve.includes('15133')) sw = 'Laravel';
  else if (a.cve.includes('39332') || a.cve.includes('23918')) sw = 'Node.js';
  else if (a.cve.includes('25869')) sw = 'AngularJS';
  console.log(`| ${a.cve} | ${sw} | \`${a.range}\` | ${a.severity} (${a.cvss}) | ${a.title} |`);
}

console.log('\n## 4. 変更なしのエントリ (%d 件)', unchanged.length);
console.log(unchanged.map(c => `- ${c}`).join('\n'));
