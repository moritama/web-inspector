/**
 * v1.8.1 T04: 週次の DB 更新ワークフロー（.github/workflows/advisory-db-update.yml）に、対応表の突き合わせのステップを足す（§5.4）
 *
 * - 既存のワークフロー（週次、月曜 05:23 JST）に、scripts/advisories/check-distro-map.mjs を実行するステップを足す。新しいワークフローは作らない
 * - 突き合わせは build-db（build-report.json を作り直す）の後、PR の本文を作る pr-plan の前。pr-plan には build-report.json を渡す
 * - 失敗してもジョブを止めない方法は、continue-on-error ではなく、スクリプトが「未確認」を記録して 0 で終わること
 * - アクションは SHA 固定。actionlint はインストールされている環境でだけ実行する
 * YAML の解析器は使わず（依存パッケージを足さない）、文字列として確かめる。
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';

const WORKFLOWS_DIR = path.join(REPO_ROOT, '.github', 'workflows');
const UPDATE_YML_PATH = path.join(WORKFLOWS_DIR, 'advisory-db-update.yml');

const CHECK_RE = /\bnode\s+scripts\/advisories\/check-distro-map\.mjs\b/;
const BUILD_DB_RE = /\bnode\s+scripts\/advisories\/build-db\.mjs\b/;
const PR_PLAN_RE = /\bnode\s+scripts\/advisories\/pr-plan\.mjs\b/;

/** コメント行と行末のコメントを除いた行（`#` の前に空白があるものだけ。このワークフローの書き方の範囲で足りる簡易版） */
function stripComments(yml: string): string[] {
  return yml.split(/\r?\n/).map((line) => {
    if (/^\s*#/.test(line)) return '';
    const idx = line.search(/\s#\s/);
    return idx >= 0 ? line.slice(0, idx) : line;
  });
}

/** steps: の各ステップ（`- ` で始まる行から次のステップの前まで）。インデントは最初のステップに合わせる */
function stepBlocks(lines: string[]): string[][] {
  const stepsIdx = lines.findIndex((l) => /^\s+steps:\s*$/.test(l));
  if (stepsIdx < 0) return [];
  const rest = lines.slice(stepsIdx + 1);
  const first = rest.find((l) => /^\s+-\s/.test(l));
  if (!first) return [];
  const indent = first.search(/-/);
  const blocks: string[][] = [];
  for (const line of rest) {
    if (line.trim() === '') {
      if (blocks.length) blocks[blocks.length - 1].push(line);
      continue;
    }
    const lead = line.search(/\S/);
    if (lead < indent) break;
    if (lead === indent && line.slice(lead).startsWith('- ')) blocks.push([line]);
    else if (blocks.length) blocks[blocks.length - 1].push(line);
  }
  return blocks;
}

/** uses: の値のうち、40 桁の commit SHA で固定されていないもの（ローカルのアクション ./ と docker:// は対象外） */
function unpinnedUses(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    const m = line.match(/^\s*(?:-\s+)?uses:\s*['"]?([^'"\s]+)['"]?\s*$/);
    if (!m) continue;
    const ref = m[1];
    if (ref.startsWith('./') || ref.startsWith('docker://')) continue;
    if (!/^[^@\s]+@[0-9a-f]{40}$/.test(ref)) out.push(ref);
  }
  return out;
}

const stepIndex = (steps: string[][], re: RegExp) => steps.findIndex((s) => s.some((l) => re.test(l)));

describe('T04: 検査の補助関数（自己確認）', () => {
  it('stepBlocks: ステップを分け、複数行の run: | の中身も同じステップに含めること', () => {
    const sample = [
      'jobs:',
      '  update:',
      '    steps:',
      '      - name: a',
      '        run: echo a',
      '      - name: b',
      '        run: |',
      '          echo b1',
      '',
      '          echo b2',
      '      - uses: actions/checkout@' + 'a'.repeat(40),
      '  other:',
      '    runs-on: ubuntu-latest',
    ];
    const steps = stepBlocks(sample);
    expect(steps).toHaveLength(3);
    expect(steps[1].join('\n')).toContain('echo b2');
    expect(stepIndex(steps, /echo b2/)).toBe(1);
  });
});

describe('T04: advisory-db-update.yml に対応表の突き合わせのステップがある', () => {
  const raw = fs.readFileSync(UPDATE_YML_PATH, 'utf-8');
  const lines = stripComments(raw);
  const steps = stepBlocks(lines);

  it('scripts/advisories/check-distro-map.mjs を実行するステップがあること', () => {
    expect(stepIndex(steps, CHECK_RE), 'check-distro-map.mjs を実行するステップがありません').toBeGreaterThanOrEqual(0);
  });

  it('突き合わせは build-db の後（build-report.json が作り直された後）、pr-plan の前に実行すること', () => {
    const buildIdx = stepIndex(steps, BUILD_DB_RE);
    const checkIdx = stepIndex(steps, CHECK_RE);
    const planIdx = stepIndex(steps, PR_PLAN_RE);
    expect(buildIdx).toBeGreaterThanOrEqual(0);
    expect(planIdx).toBeGreaterThanOrEqual(0);
    expect(checkIdx, 'check-distro-map.mjs が build-db より前にあります').toBeGreaterThan(buildIdx);
    expect(checkIdx, 'check-distro-map.mjs が pr-plan より後にあります').toBeLessThan(planIdx);
  });

  it('pr-plan には --build-report で build-report.json を渡すこと（PR の本文に「対応表のずれ」を載せる）', () => {
    const plan = steps[stepIndex(steps, PR_PLAN_RE)] ?? [];
    expect(plan.join('\n')).toMatch(/--build-report\s+['"]?data\/advisories\/build-report\.json['"]?/);
  });

  it('ワークフローに continue-on-error を使わないこと（失敗してもジョブを止めないのは、スクリプトが 0 で終わることで行う）', () => {
    expect(lines.filter((l) => /\bcontinue-on-error\s*:/.test(l))).toEqual([]);
  });

  it('突き合わせのコマンドの終了コードを `|| true` などで握りつぶさないこと（スクリプトの異常は見えるようにする）', () => {
    const step = steps[stepIndex(steps, CHECK_RE)] ?? [];
    const line = step.find((l) => CHECK_RE.test(l)) ?? '';
    expect(line).not.toMatch(/\|\|\s*(?:true|:|exit\s+0)\b/);
  });

  it('ワークフローのアクションは、すべて 40 桁の commit SHA で固定されていること', () => {
    expect(unpinnedUses(lines)).toEqual([]);
  });

  it('週次の実行（月曜 05:23 JST ＝ cron 23 20 * * 0）はそのままであること', () => {
    expect(raw).toMatch(/cron:\s*['"]23 20 \* \* 0['"]/);
  });

  it('突き合わせを実行するワークフローは advisory-db-update.yml だけであること（新しいワークフローを作らない）', () => {
    const files = fs.readdirSync(WORKFLOWS_DIR).filter((f) => /\.ya?ml$/.test(f));
    const using = files.filter((f) => CHECK_RE.test(fs.readFileSync(path.join(WORKFLOWS_DIR, f), 'utf-8')));
    expect(using).toEqual(['advisory-db-update.yml']);
  });
});

const actionlintAvailable = spawnSync('actionlint', ['-version'], { encoding: 'utf-8' }).status === 0;

describe('T04: actionlint', () => {
  it.skipIf(!actionlintAvailable)('actionlint が advisory-db-update.yml にエラーを出さないこと（actionlint がある環境だけ）', () => {
    const r = spawnSync('actionlint', ['-no-color', UPDATE_YML_PATH], { cwd: REPO_ROOT, encoding: 'utf-8' });
    expect(r.status, `${r.stdout}\n${r.stderr}`).toBe(0);
  });
});
