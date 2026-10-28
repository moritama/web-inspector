#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * 脆弱性DB 差分レポート・変更分類 (scripts/advisories/diff-db.mjs)
 *
 * 自動更新PRの本文と「自動マージしてよいか」の判定に使う。
 *
 * 分類 (classification):
 *   none  : メタデータ以外に変更なし → PR を作成しない
 *   minor : 追加・スコア/範囲の軽微な更新のみ → 自動マージ可 (リポジトリ変数 ADVISORY_AUTO_MERGE=true の場合)
 *   major : 人間のレビュー必須
 *           - curated エントリの削除 / 製品の削除
 *           - auto エントリの大量削除 (max(3件, 10%) 超)
 *           - EOL → Supported への逆行 (上流データ異常の典型)
 *           - 取得失敗ソースあり (syncStatus=partial)
 *           - DB サイズ 50% 超の増加
 *
 * 使い方:
 *   node scripts/advisories/diff-db.mjs --base <旧DB.json> --head <新DB.json> [--md out.md] [--json out.json]
 *   (--base 省略時は `git show origin/main:src/detection/advisory-db.json`)
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { PATHS } from './lib/util.mjs';

function indexDb(db) {
  const advisories = new Map();
  const eol = new Map();
  for (const [key, lib] of Object.entries(db?.libraries || {})) {
    for (const v of lib.versions || []) advisories.set(`${key}:${v.cve}`, { key, ...v });
    for (const e of lib.eol || []) eol.set(`${key}:${e.cycle}`, { key, ...e });
  }
  return { advisories, eol, products: new Set(Object.keys(db?.libraries || {})) };
}

export function diffDatabases(base, head, { baseSize = 0, headSize = 0, refreshDays = 0 } = {}) {
  const b = indexDb(base);
  const h = indexDb(head);
  const added = [];
  const removed = [];
  const changed = [];
  const eolChanged = [];
  const reasonsMajor = [];

  for (const [k, v] of h.advisories) {
    if (!b.advisories.has(k)) added.push(v);
    else {
      const o = b.advisories.get(k);
      const fields = ['range', 'cvssScore', 'severity', 'fixedVersion', 'kev'].filter((f) => JSON.stringify(o[f]) !== JSON.stringify(v[f]));
      if (fields.length) changed.push({ key: v.key, cve: v.cve, fields, before: Object.fromEntries(fields.map((f) => [f, o[f]])), after: Object.fromEntries(fields.map((f) => [f, v[f]])) });
    }
  }
  for (const [k, v] of b.advisories) if (!h.advisories.has(k)) removed.push(v);
  for (const [k, v] of h.eol) {
    const o = b.eol.get(k);
    if (!o) eolChanged.push({ key: v.key, cycle: v.cycle, before: null, after: v.status });
    else if (o.status !== v.status || o.eolDate !== v.eolDate) eolChanged.push({ key: v.key, cycle: v.cycle, before: o.status, after: v.status, eolDate: v.eolDate });
  }

  for (const p of b.products) if (!h.products.has(p)) reasonsMajor.push(`製品が削除されました: ${p}`);
  const removedCurated = removed.filter((r) => r.origin === 'curated' || !r.origin);
  if (removedCurated.length) reasonsMajor.push(`レビュー済み (curated/旧DB) エントリの削除: ${removedCurated.map((r) => r.cve).join(', ')}`);
  const baseAuto = [...b.advisories.values()].filter((v) => v.origin === 'auto').length;
  const removedAuto = removed.filter((r) => r.origin === 'auto').length;
  if (removedAuto > Math.max(3, Math.ceil(baseAuto * 0.1))) reasonsMajor.push(`自動取得エントリの大量削除: ${removedAuto} 件`);
  const regressions = eolChanged.filter((e) => e.before === 'EOL' && e.after === 'Supported');
  if (regressions.length) reasonsMajor.push(`EOL → Supported への逆行: ${regressions.map((e) => `${e.key} ${e.cycle}`).join(', ')}`);
  if (head?.syncStatus && head.syncStatus !== 'success') reasonsMajor.push(`一部ソースの取得に失敗 (syncStatus=${head.syncStatus})`);
  if (baseSize > 0 && headSize > baseSize * 1.5) reasonsMajor.push(`DBサイズが50%超増加: ${baseSize} → ${headSize} bytes`);

  const hasChange = added.length + removed.length + changed.length + eolChanged.length > 0 || base?.schemaVersion !== head?.schemaVersion;
  let classification = !hasChange ? 'none' : reasonsMajor.length ? 'major' : 'minor';
  // 内容に変化がなくても、出荷中DBの生成日が古くなりすぎた場合は鮮度更新として minor 扱いにする
  // (拡張機能は generatedAt から 31 日超で「DB鮮度」警告を表示するため)
  let freshnessRefresh = false;
  if (classification === 'none' && refreshDays > 0 && base?.generatedAt && head?.generatedAt) {
    const ageDays = (new Date(head.generatedAt).getTime() - new Date(base.generatedAt).getTime()) / 86400_000;
    if (ageDays >= refreshDays) {
      classification = 'minor';
      freshnessRefresh = true;
    }
  }
  return { classification, freshnessRefresh, reasonsMajor, added, removed, changed, eolChanged, base: { dataVersion: base?.dataVersion, schemaVersion: base?.schemaVersion }, head: { dataVersion: head?.dataVersion, schemaVersion: head?.schemaVersion, syncStatus: head?.syncStatus } };
}

export function renderMarkdown(d) {
  const lines = [];
  const badge = { none: '変更なし', minor: '🟢 minor (自動マージ可)', major: '🔴 major (要レビュー)' }[d.classification];
  lines.push('## 脆弱性DB 自動更新');
  lines.push('');
  lines.push(`- 分類: **${badge}**`);
  lines.push(`- dataVersion: \`${d.base.dataVersion}\` → \`${d.head.dataVersion}\` (schema ${d.base.schemaVersion} → ${d.head.schemaVersion})`);
  lines.push(`- 追加 ${d.added.length} / 削除 ${d.removed.length} / 変更 ${d.changed.length} / EOL変更 ${d.eolChanged.length}`);
  if (d.freshnessRefresh) lines.push('- 内容の変更はありませんが、出荷中DBの生成日が古くなったため鮮度更新リリースを行います。');
  if (d.reasonsMajor.length) {
    lines.push('');
    lines.push('### ⚠️ 人間のレビューが必要な理由');
    for (const r of d.reasonsMajor) lines.push(`- ${r}`);
  }
  const table = (title, rows, cols) => {
    if (!rows.length) return;
    lines.push('', `### ${title}`, '', `| ${cols.map((c) => c[0]).join(' | ')} |`, `| ${cols.map(() => '---').join(' | ')} |`);
    for (const r of rows.slice(0, 200)) lines.push(`| ${cols.map((c) => String(c[1](r) ?? '').replace(/\|/g, '\\|')).join(' | ')} |`);
    if (rows.length > 200) lines.push(`| … 他 ${rows.length - 200} 件 | |`);
  };
  table('追加', d.added, [['製品', (r) => r.key], ['ID', (r) => r.cve], ['CVSS', (r) => r.cvssScore], ['範囲', (r) => `\`${r.range}\``], ['KEV', (r) => (r.kev ? '✔' : '')], ['出典', (r) => r.scoreSource]]);
  table('削除', d.removed, [['製品', (r) => r.key], ['ID', (r) => r.cve], ['origin', (r) => r.origin || 'legacy']]);
  table('変更', d.changed, [['製品', (r) => r.key], ['ID', (r) => r.cve], ['項目', (r) => r.fields.join(', ')], ['変更前', (r) => `\`${JSON.stringify(r.before)}\``], ['変更後', (r) => `\`${JSON.stringify(r.after)}\``]]);
  table('EOL 変更', d.eolChanged, [['製品', (r) => r.key], ['サイクル', (r) => r.cycle], ['変更前', (r) => r.before ?? '(新規)'], ['変更後', (r) => r.after], ['EOL日', (r) => r.eolDate ?? '']]);
  lines.push('', '---', 'レビュー観点: 範囲の妥当性 (ベンダー公式アドバイザリとの一致) / 条件付き脆弱性の注記 / EOL 判定の逆行有無。詳細は `data/advisories/build-report.json`。');
  return `${lines.join('\n')}\n`;
}

function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--')) a[argv[i].slice(2)] = argv[i + 1]?.startsWith('--') ? true : argv[++i];
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv);
  let baseText;
  if (args.base) baseText = fs.readFileSync(args.base, 'utf-8');
  else {
    try {
      baseText = execFileSync('git', ['show', `${args['base-ref'] || 'origin/main'}:src/detection/advisory-db.json`], { encoding: 'utf-8', maxBuffer: 16 * 1024 * 1024 });
    } catch {
      baseText = '{}';
    }
  }
  const headText = fs.readFileSync(args.head || PATHS.outputDb, 'utf-8');
  const d = diffDatabases(JSON.parse(baseText), JSON.parse(headText), {
    baseSize: baseText.length,
    headSize: headText.length,
    refreshDays: args['refresh-days'] ? Number(args['refresh-days']) : 0,
  });
  const md = renderMarkdown(d);
  if (args.md) fs.writeFileSync(args.md, md, 'utf-8');
  if (args.json) fs.writeFileSync(args.json, `${JSON.stringify(d, null, 2)}\n`, 'utf-8');
  if (!args.md) process.stdout.write(md);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `classification=${d.classification}\n`);
  console.error(`[diff-db] classification=${d.classification}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
