#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * v1.6.6 総合チェック (scripts/dev/check-v1.6.6.mjs)
 *
 * 改修指示書 docs/dev/v1.6.6/INSTRUCTIONS.md の完了条件のうち、機械的に確認できるものを一括検査し、
 * 結果を docs/dev/v1.6.6/check-result.json に保存する（完了報告書の根拠として使う）。
 *
 * 使い方:
 *   node scripts/dev/check-v1.6.6.mjs            # 静的検査 + npm test + build + DB検証
 *   node scripts/dev/check-v1.6.6.mjs --static   # 静的検査のみ（高速）
 *   node scripts/dev/check-v1.6.6.mjs --e2e      # 上記に加えて E2E (npm run test:e2e)
 * 終了コード: すべて PASS なら 0、それ以外は 1
 */

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TARGET_VERSION = '1.6.6';
const OUT = path.join(ROOT, 'docs', 'dev', 'v1.6.6', 'check-result.json');

/** v1.6.6 で skip を外すべき受け入れテスト（describe 名の先頭） */
const P0_ACCEPTANCE = ['SPEC-01', 'SPEC-02', 'SPEC-04', 'SPEC-06', 'SPEC-09', 'DOC-01', 'DOC-02'];
/** P1 として skip のまま残してよいもの */
const P1_ACCEPTANCE = ['SPEC-07 / SPEC-08', 'SPEC-10', 'SPEC-12'];

const args = new Set(process.argv.slice(2));
const results = [];
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf-8');
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));

function record(id, title, ok, detail = '') {
  results.push({ id, title, status: ok ? 'PASS' : 'FAIL', detail });
  console.log(`${ok ? '  [PASS]' : '  [FAIL]'} ${id} ${title}${detail ? ` — ${detail}` : ''}`);
}

function walk(dir, exts, out = []) {
  for (const e of fs.readdirSync(path.join(ROOT, dir), { withFileTypes: true })) {
    const rel = path.join(dir, e.name);
    if (e.isDirectory()) walk(rel, exts, out);
    else if (exts.some((x) => e.name.endsWith(x))) out.push(rel);
  }
  return out;
}

// ---------------------------------------------------------------- 静的検査
console.log('[check] 静的検査');

// C01 バージョン整合
{
  const issues = [];
  const manifest = JSON.parse(read('public/manifest.json'));
  const pkg = JSON.parse(read('package.json'));
  if (manifest.version !== TARGET_VERSION) issues.push(`manifest=${manifest.version}`);
  if (pkg.version !== TARGET_VERSION) issues.push(`package.json=${pkg.version}`);
  if (exists('package-lock.json')) {
    const lock = JSON.parse(read('package-lock.json'));
    if (lock.version !== TARGET_VERSION) issues.push(`package-lock=${lock.version}`);
  }
  if (!read('src/detection/rules/index.ts').includes(`RULES_VERSION = '${TARGET_VERSION}'`)) issues.push('RULES_VERSION');
  for (const f of ['src/background/service-worker.ts', 'src/popup/popup.ts', 'src/dashboard/dashboard.ts']) {
    const src = read(f);
    const m = src.match(/'(\d+\.\d+\.\d+)'/g) || [];
    const stale = m.filter((v) => /^'1\.6\.[0-5]'$/.test(v));
    if (stale.length) issues.push(`${f} に旧バージョン文字列 ${[...new Set(stale)].join(',')}`);
  }
  for (const f of ['popup.html', 'dashboard.html', 'src/popup/popup.html', 'src/dashboard/dashboard.html']) {
    if (exists(f) && !read(f).includes(`v${TARGET_VERSION}`)) issues.push(`${f} のバッジ`);
  }
  if (!read('README.md').includes(`version-${TARGET_VERSION}-`)) issues.push('README バッジ');
  record('C01', `バージョンが ${TARGET_VERSION} に統一されている`, issues.length === 0, issues.join(' / '));
}

// C02 インラインイベントハンドラが無い (IMPL-01)
{
  const hits = [];
  for (const f of [...walk('src', ['.ts', '.html']), 'popup.html', 'dashboard.html'].filter(exists)) {
    read(f).split('\n').forEach((line, i) => {
      if (/\son(click|change|input|submit|load|error|mouseover|keydown|keyup)\s*=\s*["'`{$]/i.test(line)) hits.push(`${f}:${i + 1}`);
    });
  }
  record('C02', 'インラインイベントハンドラ (onclick= 等) が残っていない', hits.length === 0, hits.slice(0, 5).join(', '));
}

// C03 P0 受け入れテストの skip 解除
{
  const src = read('tests/review-v1.6.5-acceptance.test.ts');
  const blocks = src.split(/\ndescribe\(/).slice(1).map((b) => ({ title: (b.match(/^'([^']+)'/) || [])[1] || '', body: b }));
  const stillSkipped = [];
  const missing = [];
  for (const id of P0_ACCEPTANCE) {
    const blk = blocks.find((b) => b.title.startsWith(id));
    if (!blk) missing.push(id);
    else if (/\bit\.skip\b|\bdescribe\.skip\b|\bit\.todo\b/.test(blk.body)) stillSkipped.push(id);
  }
  const expectEdited = /expect\(\s*true\s*\)|toBeTruthy\(\)\s*;\s*\/\/\s*TODO/.test(src);
  record(
    'C03',
    `P0 受け入れテスト (${P0_ACCEPTANCE.join(', ')}) の skip が外れている`,
    stillSkipped.length === 0 && missing.length === 0 && !expectEdited,
    [stillSkipped.length ? `skip のまま: ${stillSkipped.join(', ')}` : '', missing.length ? `describe が見つからない: ${missing.join(', ')}` : '', expectEdited ? '期待値が書き換えられた疑い' : '']
      .filter(Boolean)
      .join(' / ')
  );
  const p1Present = P1_ACCEPTANCE.filter((id) => blocks.some((b) => b.title.startsWith(id)));
  record('C04', 'P1 受け入れテストが削除されていない', p1Present.length === P1_ACCEPTANCE.length, `存在: ${p1Present.join(', ')}`);
}

// C05 旧DB・旧エンジンの削除 (DOC-09)
{
  const legacy = ['src/security/cve/cve-database.json', 'src/security/cve/cve-engine.ts', 'src/security/eol/eol-database.json', 'src/security/eol/eol-engine.ts'].filter(exists);
  const refs = [];
  for (const f of [...walk('src', ['.ts']), ...walk('tests', ['.ts', '.mjs'])]) {
    if (/cve-engine|eol-engine|cve-database|eol-database/.test(read(f))) refs.push(f);
  }
  record('C05', '旧DB・旧エンジンが削除され、参照も残っていない', legacy.length === 0 && refs.length === 0, [...legacy, ...refs].join(', '));
}

// C06 Lodash / Moment ルール (DOC-02)
{
  const rules = JSON.parse(read('src/detection/rules/frontend.json'));
  const ids = new Set(rules.map((r) => r.id));
  const sw = read('src/background/service-worker.ts');
  const underscoreGuard = /cloneDeep/.test(sw);
  record('C06', 'lodash / moment ルールが存在し、Underscore との誤認防止がある', ids.has('lodash') && ids.has('moment') && underscoreGuard, `lodash=${ids.has('lodash')} moment=${ids.has('moment')} cloneDeepGuard=${underscoreGuard}`);
}

// C07 escapeHtml / safeHref の共通化 (IMPL-03)
{
  const ok = exists('src/shared/html.ts') && /export function safeHref/.test(read('src/shared/html.ts')) && /export function escapeHtml/.test(read('src/shared/html.ts'));
  const dupes = ['src/popup/popup.ts', 'src/dashboard/dashboard.ts'].filter((f) => /function escapeHtml\(/.test(read(f)));
  record('C07', 'escapeHtml / safeHref が src/shared/html.ts に共通化されている', ok && dupes.length === 0, dupes.length ? `重複定義: ${dupes.join(', ')}` : '');
}

// C08 新規テストファイル
{
  const required = ['tests/rule-reachability.test.ts', 'tests/ui-escaping.test.ts'];
  const missing = required.filter((f) => !exists(f));
  const historyTest = walk('tests', ['.ts']).some((f) => /history/i.test(f) && /DELETE_HISTORY_ITEM|onclick/.test(read(f)));
  record('C08', '指示書で求めた新規テストが存在する', missing.length === 0 && historyTest, [missing.length ? `未作成: ${missing.join(', ')}` : '', historyTest ? '' : '履歴ボタンのテストが見つからない'].filter(Boolean).join(' / '));
}

// C09 変更禁止領域が変更されていない
{
  const git = spawnSync('git', ['diff', '--name-only', 'main...HEAD'], { cwd: ROOT, encoding: 'utf-8' });
  if (git.status !== 0) {
    record('C09', '変更禁止領域が変更されていない', false, 'git diff main...HEAD を実行できません（main ブランチが無い可能性）');
  } else {
    const forbidden = git.stdout
      .split('\n')
      .filter(Boolean)
      .filter((f) => /^(src\/detection\/advisory-db\.json|data\/advisories\/|scripts\/advisories\/|\.github\/workflows\/|scripts\/cws-publish\.mjs|docs\/REVIEW_v1\.6\.5\.md)/.test(f));
    record('C09', '変更禁止領域が変更されていない', forbidden.length === 0, forbidden.join(', '));
  }
}

// C12 作業キット（指示書・プロンプト・チェックスクリプト等）が作業中に変更されていない
{
  const kit = spawnSync('git', ['log', '--format=%H', '-1', '--grep=v1.6.6 development kit'], { cwd: ROOT, encoding: 'utf-8' });
  const base = (kit.stdout || '').trim();
  if (kit.status !== 0 || !base) {
    record('C12', '作業キットが変更されていない', false, 'キットのコミット（"v1.6.6 development kit"）が見つかりません');
  } else {
    const diff = spawnSync('git', ['diff', '--name-only', `${base}..HEAD`], { cwd: ROOT, encoding: 'utf-8' });
    const changed = (diff.stdout || '')
      .split('\n')
      .filter(Boolean)
      .filter((f) => /^(AGENTS\.md$|\.agents\/|scripts\/dev\/|docs\/dev\/v1\.6\.6\/(INSTRUCTIONS|TASK_PROMPT|REPORT_PROMPT|README|REPORT_TEMPLATE)\.md$)/.test(f));
    record('C12', '作業キットが変更されていない', diff.status === 0 && changed.length === 0, changed.join(', '));
  }
}

// C10 作業記録・報告書
{
  const wl = exists('docs/dev/v1.6.6/WORKLOG.md') ? read('docs/dev/v1.6.6/WORKLOG.md') : '';
  const tasksLogged = new Set((wl.match(/^## T(0[1-9]|1[0-2])\b/gm) || []).map((x) => x.trim())).size;
  record('C10', 'WORKLOG に T01〜T12 すべての記録がある', tasksLogged >= 12, `記録済みタスク数: ${tasksLogged}/12`);
  const report = exists('docs/dev/v1.6.6/COMPLETION_REPORT.md') ? read('docs/dev/v1.6.6/COMPLETION_REPORT.md') : '';
  const placeholders = (report.match(/<[^>\n]{1,40}>/g) || []).filter((p) => !/^<(br|code|kbd)/i.test(p));
  record('C11', '完了報告書が作成され、未記入の <...> が残っていない', report.length > 0 && placeholders.length === 0, report ? (placeholders.length ? `未記入: ${placeholders.slice(0, 5).join(' ')}` : '') : '未作成（最後に作成する場合はこの項目のみ FAIL で正常）');
}

// ---------------------------------------------------------------- コマンド実行
function run(id, title, cmd, cmdArgs) {
  console.log(`[check] ${cmd} ${cmdArgs.join(' ')}`);
  const started = Date.now();
  const r = spawnSync(cmd, cmdArgs, { cwd: ROOT, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024, shell: process.platform === 'win32' });
  const out = `${r.stdout || ''}\n${r.stderr || ''}`;
  const summary = (out.match(/Tests\s+[^\n]+/g) || []).pop() || '';
  record(id, title, r.status === 0, `${summary.trim()} (${Math.round((Date.now() - started) / 1000)}s)`);
  return out;
}

if (!args.has('--static')) {
  run('R01', 'npm test (typecheck + links + vitest)', 'npm', ['test']);
  const buildOut = run('R02', 'npm run build', 'npm', ['run', 'build']);
  const cs = path.join(ROOT, 'dist', 'content', 'content-script.js');
  if (fs.existsSync(cs)) {
    const kb = fs.statSync(cs).size / 1024;
    record('R03', 'content-script.js が 40KB 以下', kb <= 40, `${kb.toFixed(1)} KB`);
    // content_scripts は通常スクリプトとして読み込まれるため、モジュール構文が入ると動かない
    const code = fs.readFileSync(cs, 'utf-8');
    const moduleSyntax = /(^|[;\n}])\s*(import\s*[{*\w"']|export\s*[{*\w])/.test(code);
    record('R07', 'content-script.js に import / export 文が無い（共有チャンク化していない）', !moduleSyntax, moduleSyntax ? 'モジュール構文を検出。service-worker と共有するモジュールを import していないか確認' : '');
  } else {
    record('R03', 'content-script.js が 40KB 以下', false, `dist/content/content-script.js が無い ${buildOut.slice(-200)}`);
  }
  run('R04', 'npm run advisories:validate', 'npm', ['run', 'advisories:validate']);
  run('R05', 'npm run advisories:verify-nvd', 'npm', ['run', 'advisories:verify-nvd']);
  if (args.has('--e2e')) run('R06', 'npm run test:e2e', 'npm', ['run', 'test:e2e']);
}

// ---------------------------------------------------------------- 出力
const failed = results.filter((r) => r.status === 'FAIL');
const payload = {
  checkedAt: new Date().toISOString(),
  targetVersion: TARGET_VERSION,
  mode: args.has('--static') ? 'static' : args.has('--e2e') ? 'full+e2e' : 'full',
  passed: results.length - failed.length,
  failed: failed.length,
  results,
};
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(payload, null, 2)}\n`, 'utf-8');
console.log(`\n[check] ${payload.passed} PASS / ${payload.failed} FAIL → ${path.relative(ROOT, OUT)}`);
process.exit(failed.length === 0 ? 0 : 1);
