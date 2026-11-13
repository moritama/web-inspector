/**
 * CI の定義（v1.8.0 T02）
 *
 * .github/workflows/ci.yml に
 *   - ジョブ db-release-rehearsal（DB だけのリリースの予行）を足す。既存のジョブと同じく、アクションは SHA 固定、permissions は contents: read
 *   - build の後に scripts/ci/check-size.mjs を実行する
 * ことを、YAML の文字列として確かめる（依存パッケージを足さないため、YAML の解析器は使わない）。
 * actionlint は、インストールされている環境でだけ実行する（CI の実行環境には入っていない）。
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';

const CI_YML_PATH = path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml');

function readCiYml(): string {
  return fs.readFileSync(CI_YML_PATH, 'utf-8');
}

/** コメント行と行末のコメントを除いた行（`#` は引用符の外にあるものだけ。ci.yml の書き方の範囲で足りる簡易版） */
function stripComments(yml: string): string[] {
  return yml.split(/\r?\n/).map((line) => {
    if (/^\s*#/.test(line)) return '';
    const idx = line.search(/\s#\s/);
    return idx >= 0 ? line.slice(0, idx) : line;
  });
}

/** jobs: の直下のジョブ ID と、その範囲の行 */
function jobBlocks(yml: string): Map<string, string[]> {
  const lines = stripComments(yml);
  const jobsIdx = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  const blocks = new Map<string, string[]>();
  if (jobsIdx < 0) return blocks;
  let current: string | null = null;
  for (const line of lines.slice(jobsIdx + 1)) {
    if (/^\S/.test(line)) break; // jobs: の外に出た
    const m = line.match(/^ {2}([A-Za-z_][A-Za-z0-9_-]*):\s*$/);
    if (m) {
      current = m[1];
      blocks.set(current, []);
      continue;
    }
    if (current) blocks.get(current)?.push(line);
  }
  return blocks;
}

/** uses: の値のうち、40 桁の commit SHA で固定されていないもの（ローカルのアクション ./ と docker:// は対象外） */
function unpinnedUses(yml: string): string[] {
  const out: string[] = [];
  for (const line of stripComments(yml)) {
    const m = line.match(/^\s*(?:-\s+)?uses:\s*['"]?([^'"\s]+)['"]?\s*$/);
    if (!m) continue;
    const ref = m[1];
    if (ref.startsWith('./') || ref.startsWith('docker://')) continue;
    if (!/^[^@\s]+@[0-9a-f]{40}$/.test(ref)) out.push(ref);
  }
  return out;
}

/** ブロックの中の permissions: の内容（無ければ null）。`permissions: read-all` のような 1 行の書き方はその値を返す */
function permissionsOf(lines: string[], indent: number): string[] | null {
  const pad = ' '.repeat(indent);
  const idx = lines.findIndex((l) => l.startsWith(`${pad}permissions:`) && !l.startsWith(`${pad} `));
  if (idx < 0) return null;
  const inline = lines[idx].slice(`${pad}permissions:`.length).trim();
  if (inline) return [inline];
  const body: string[] = [];
  for (const l of lines.slice(idx + 1)) {
    if (l.trim() === '') continue;
    if (!l.startsWith(`${pad} `)) break;
    body.push(l.trim());
  }
  return body;
}

/** run: を含む行の位置（ブロック内の行番号）。複数行の run: | の中身も行として探す */
function indexOfLine(lines: string[], re: RegExp): number {
  return lines.findIndex((l) => re.test(l));
}

describe('T02: 検査の補助関数（自己確認）', () => {
  it('unpinnedUses: タグや枝で指定したアクションを見つけ、SHA で固定したものは見逃すこと', () => {
    const sha = 'a'.repeat(40);
    const sample = [
      'steps:',
      `  - uses: actions/checkout@${sha} # v7`,
      '  - uses: actions/setup-node@v4',
      "  - uses: 'owner/action@main'",
      '  - uses: ./local-action',
    ].join('\n');
    expect(unpinnedUses(sample)).toEqual(['actions/setup-node@v4', 'owner/action@main']);
  });

  it('jobBlocks / permissionsOf: ジョブを分け、ジョブの permissions を読み取ること', () => {
    const sample = [
      'permissions:',
      '  contents: read',
      'jobs:',
      '  a:',
      '    runs-on: ubuntu-latest',
      '    permissions:',
      '      contents: write',
      '    steps:',
      '      - run: echo a',
      '  b:',
      '    runs-on: ubuntu-latest',
    ].join('\n');
    const blocks = jobBlocks(sample);
    expect([...blocks.keys()]).toEqual(['a', 'b']);
    expect(permissionsOf(blocks.get('a') ?? [], 4)).toEqual(['contents: write']);
    expect(permissionsOf(blocks.get('b') ?? [], 4)).toBeNull();
    expect(permissionsOf(sample.split('\n'), 0)).toEqual(['contents: read']);
  });
});

describe('T02: ci.yml', () => {
  const yml = readCiYml();
  const blocks = jobBlocks(yml);

  it('ジョブ db-release-rehearsal があること', () => {
    expect([...blocks.keys()]).toContain('db-release-rehearsal');
  });

  it('既存のジョブ verify は残っていること', () => {
    expect([...blocks.keys()]).toContain('verify');
  });

  it('db-release-rehearsal は、依存を入れて（npm ci）から scripts/ci/rehearse-db-release.mjs を実行すること', () => {
    const job = blocks.get('db-release-rehearsal') ?? [];
    const ciIdx = indexOfLine(job, /\bnpm ci\b/);
    const rehearseIdx = indexOfLine(job, /\bnode\s+scripts\/ci\/rehearse-db-release\.mjs\b/);
    expect(rehearseIdx, 'scripts/ci/rehearse-db-release.mjs を実行する手順がありません').toBeGreaterThanOrEqual(0);
    expect(ciIdx, 'npm ci の手順がありません').toBeGreaterThanOrEqual(0);
    expect(ciIdx).toBeLessThan(rehearseIdx);
  });

  it('db-release-rehearsal はリポジトリを取得し（actions/checkout）、Node.js を用意する（actions/setup-node）こと', () => {
    const job = (blocks.get('db-release-rehearsal') ?? []).join('\n');
    expect(job).toMatch(/uses:\s*['"]?actions\/checkout@/);
    expect(job).toMatch(/uses:\s*['"]?actions\/setup-node@/);
  });

  it('ci.yml のアクションは、すべて 40 桁の commit SHA で固定されていること', () => {
    expect(unpinnedUses(yml)).toEqual([]);
  });

  it('ワークフロー全体の permissions は contents: read だけであること', () => {
    expect(permissionsOf(stripComments(yml), 0)).toEqual(['contents: read']);
  });

  it('db-release-rehearsal の permissions は、指定するなら contents: read だけであること（書き込み権限を持たない）', () => {
    const perms = permissionsOf(blocks.get('db-release-rehearsal') ?? [], 4);
    if (perms !== null) expect(perms).toEqual(['contents: read']);
  });

  it('ci.yml のどこにも書き込み権限（write・write-all）が無いこと', () => {
    const lines = stripComments(yml);
    expect(lines.filter((l) => /:\s*write\b/.test(l) || /\bwrite-all\b/.test(l))).toEqual([]);
  });

  it('同じジョブの中で、npm run build の後に scripts/ci/check-size.mjs を実行すること', () => {
    const found = [...blocks.entries()].filter(([, lines]) => {
      const buildIdx = indexOfLine(lines, /\bnpm run build\b/);
      const sizeIdx = indexOfLine(lines, /\bnode\s+scripts\/ci\/check-size\.mjs\b/);
      return buildIdx >= 0 && sizeIdx > buildIdx;
    });
    expect(found.map(([id]) => id), 'build の後に check-size.mjs を実行するジョブがありません').not.toEqual([]);
  });

  it('check-size.mjs を build より前に実行するジョブが無いこと（陰性: dist が無い状態で測らない）', () => {
    for (const [id, lines] of blocks) {
      const sizeIdx = indexOfLine(lines, /\bnode\s+scripts\/ci\/check-size\.mjs\b/);
      if (sizeIdx < 0) continue;
      const buildIdx = indexOfLine(lines, /\bnpm run build\b/);
      expect(buildIdx, `${id}: check-size.mjs の前に npm run build がありません`).toBeGreaterThanOrEqual(0);
      expect(buildIdx, `${id}: check-size.mjs が npm run build より前にあります`).toBeLessThan(sizeIdx);
    }
  });
});

const actionlintAvailable = spawnSync('actionlint', ['-version'], { encoding: 'utf-8' }).status === 0;

describe('T02: actionlint', () => {
  it.skipIf(!actionlintAvailable)('actionlint が ci.yml にエラーを出さないこと（actionlint がある環境だけ）', () => {
    const r = spawnSync('actionlint', ['-no-color', CI_YML_PATH], { cwd: REPO_ROOT, encoding: 'utf-8' });
    expect(r.status, `${r.stdout}\n${r.stderr}`).toBe(0);
  });
});
