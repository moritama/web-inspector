/**
 * v1.8.1 T06: リリースの表示名を作る処理の共通化（T03 の 4 か所の重複をまとめる）
 *
 * - 表示名を作る処理は src/shared/distro-display.ts の 1 か所だけにあり、popup・dashboard・markdown・csv の 4 つの出力経路がそれを呼ぶ
 *   （呼んでいることの振る舞いの確認は tests/distro-release-display-callers.test.ts）
 * - リリース欄では inf.release を優先し、eolInfo.label は推定由来（OS のライフサイクルで判定したもの）のときだけ使う
 * - 第三者リポジトリと確信度 none の入力で、リリース欄に上流の EOL ラベル（eolInfo.label）が出ない
 */
import * as fs from 'fs';
import * as path from 'path';
import { describe, expect, it } from 'vitest';
import { formatDistroReleaseDisplay, formatDistroReleaseName } from '../src/shared/distro-display';
import type { DetectedTechnology, DistroInference, EolInfo } from '../src/shared/types';
import { REPO_ROOT } from './helpers/release-version';

/** T03 の judgeDistroEol が付ける source（OS のライフサイクルで判定した EOL の印） */
const OS_LIFECYCLE_SOURCE = 'endoflife.date（OS のライフサイクル）';
/** 第1段階の上流の EOL ラベル（同梱 DB に label を持つ製品が増えたときに出るもの）に見立てた値 */
const UPSTREAM_LABEL = 'UpstreamEolLabelMarker';

function inf(overrides: Partial<DistroInference>): DistroInference {
  return { family: 'ubuntu', release: null, candidates: [], confidence: 'none', evidence: [], ...overrides };
}

function upstreamEol(): EolInfo {
  return { status: 'EOL', eolDate: null, source: 'offline-db', recommendation: '上流のサポートが終了しています。', label: UPSTREAM_LABEL };
}

function osEol(label: string): EolInfo {
  return { status: 'Unknown', eolDate: null, source: OS_LIFECYCLE_SOURCE, recommendation: 'サーバー側で確認してください。', label };
}

type DisplayInput = Pick<DetectedTechnology, 'distroInference' | 'eolInfo'>;

describe('T06: formatDistroReleaseName（リリース → 表示名）', () => {
  it.each([
    ['ubuntu:20.04', 'Ubuntu 20.04'],
    ['debian:12', 'Debian 12'],
    ['rhel:9', 'Red Hat Enterprise Linux 9'],
    ['centos:7', 'CentOS 7'],
    ['almalinux:9', 'AlmaLinux 9'],
    ['rocky:8', 'Rocky Linux 8'],
  ])('%s → %s（T03 の表示と同じ）', (release, expected) => {
    expect(formatDistroReleaseName(release)).toBe(expected);
  });
});

describe('T06: formatDistroReleaseDisplay（リリース欄の表示）', () => {
  it('inf.release を優先する: OS のライフサイクルの label があっても、リリース名を出す', () => {
    const t: DisplayInput = {
      distroInference: inf({ release: 'ubuntu:20.04', candidates: ['ubuntu:20.04'], confidence: 'medium' }),
      eolInfo: osEol('Ubuntu 20.04 LTS（推定・確信度 中）'),
    };
    expect(formatDistroReleaseDisplay(t)).toBe(formatDistroReleaseName('ubuntu:20.04'));
  });

  it('inf.release があれば、上流の EOL ラベルを出さない', () => {
    const t: DisplayInput = {
      distroInference: inf({ release: 'debian:11', candidates: ['debian:11'], confidence: 'high' }),
      eolInfo: upstreamEol(),
    };
    const display = formatDistroReleaseDisplay(t);
    expect(display).toContain('Debian 11');
    expect(display).not.toContain(UPSTREAM_LABEL);
  });

  it.each([
    ['第三者リポジトリ（deb.sury.org）', inf({ thirdParty: { kind: 'third-party', marker: 'deb.sury.org' }, note: '第三者リポジトリの版です（deb.sury.org）。' })],
    ['バックポート（~bpo）', inf({ family: 'debian', thirdParty: { kind: 'backport', marker: '~bpo10+1' } })],
    ['確信度 none', inf({ note: 'リリースを推定できません。' })],
  ])('受け入れ条件 6: %s の入力で、リリース欄に上流の EOL ラベル（eolInfo.label）が出ない', (_label, distroInference) => {
    const display = formatDistroReleaseDisplay({ distroInference, eolInfo: upstreamEol() });
    expect(display).not.toContain(UPSTREAM_LABEL);
    expect(display.length).toBeGreaterThan(0);
  });

  it('確信度 none のリリース欄は「推定なし」', () => {
    expect(formatDistroReleaseDisplay({ distroInference: inf({}), eolInfo: upstreamEol() })).toContain('推定なし');
  });

  it('候補が 2 件以上で、OS のライフサイクルで判定した label（推定由来）があれば、それを使ってよい（全候補が入る）', () => {
    const t: DisplayInput = {
      distroInference: inf({ candidates: ['ubuntu:20.04', 'ubuntu:22.04'], confidence: 'low' }),
      eolInfo: osEol('Ubuntu 20.04 LTS / Ubuntu 22.04 LTS（推定・確信度 低）'),
    };
    const display = formatDistroReleaseDisplay(t);
    expect(display).toContain('Ubuntu 20.04');
    expect(display).toContain('Ubuntu 22.04');
  });

  it('候補が 2 件以上で、eolInfo.label が推定由来でない（上流の EOL）なら、label を使わず候補の名前を並べる', () => {
    const t: DisplayInput = {
      distroInference: inf({ candidates: ['ubuntu:20.04', 'ubuntu:22.04'], confidence: 'low' }),
      eolInfo: upstreamEol(),
    };
    const display = formatDistroReleaseDisplay(t);
    expect(display).not.toContain(UPSTREAM_LABEL);
    expect(display).toContain('Ubuntu 20.04');
    expect(display).toContain('Ubuntu 22.04');
  });

  it('eolInfo が無くても候補の名前を出す', () => {
    const display = formatDistroReleaseDisplay({ distroInference: inf({ candidates: ['debian:11', 'debian:12'], confidence: 'low' }) });
    expect(display).toContain('Debian 11');
    expect(display).toContain('Debian 12');
  });
});

describe('T06 受け入れ条件 5: リリースの表示名を作る処理が 1 か所だけにあり、4 つの出力経路がそれを呼んでいる（静的な確認）', () => {
  const SRC = path.join(REPO_ROOT, 'src');
  const OUTPUTS = ['popup/render.ts', 'dashboard/render.ts', 'export/markdown.ts', 'export/csv.ts'];
  const SHARED = 'shared/distro-display.ts';

  function walk(dir: string): string[] {
    const out: string[] = [];
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) out.push(...walk(abs));
      else if (ent.isFile() && ent.name.endsWith('.ts')) out.push(abs);
    }
    return out;
  }
  const rel = (abs: string) => path.relative(SRC, abs).split(path.sep).join('/');

  /** リリース（'ubuntu:20.04'）を表示名に変える書き方（T03 の重複していた書き方と、名前を組み立てる文字列） */
  const BUILDERS = [
    /\.replace\(\s*\/\^(?:ubuntu|debian|rhel|centos|almalinux|rocky):/,
    /['"`]Red Hat Enterprise Linux (?:['"`]|\$\{)/,
    /['"`]Rocky Linux (?:['"`]|\$\{)/,
  ];

  it.each(OUTPUTS)('%s は共通の関数（formatDistroReleaseDisplay）を src/shared/distro-display から import している', (file) => {
    const text = fs.readFileSync(path.join(SRC, file), 'utf-8');
    expect(text).toMatch(/import\s*\{[^}]*\bformatDistroReleaseDisplay\b[^}]*\}\s*from\s*['"]\.\.\/shared\/distro-display['"]/);
  });

  it('表示名を組み立てる書き方は src/shared/distro-display.ts にだけある', () => {
    const offenders: string[] = [];
    for (const abs of walk(SRC)) {
      const r = rel(abs);
      if (r === SHARED) continue;
      const text = fs.readFileSync(abs, 'utf-8');
      for (const re of BUILDERS) if (re.test(text)) offenders.push(`${r}: ${re}`);
    }
    expect(offenders).toEqual([]);
  });

  it('前提: src/shared/distro-display.ts に表示名の組み立てがある', () => {
    const text = fs.readFileSync(path.join(SRC, SHARED), 'utf-8');
    expect(text).toMatch(/Red Hat Enterprise Linux/);
    expect(text).toMatch(/export function formatDistroReleaseDisplay/);
    expect(text).toMatch(/export function formatDistroReleaseName/);
  });
});
