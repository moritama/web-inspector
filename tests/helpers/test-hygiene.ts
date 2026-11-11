/**
 * テストの衛生検査（v1.8.0 T01）の検査ロジック
 *
 * (1) 許可リスト外のテストが、同梱 DB（src/detection/advisory-db.json）を読んでいないこと
 * (2) 許可リスト外のテストに、現在の package.json の版の文字列が直接書かれていないこと
 *
 * tests/test-hygiene.test.ts から使う。違反を置いた一時ディレクトリでも検査できるよう、検査するディレクトリを引数で受け取る。
 */
import * as fs from 'fs';
import * as path from 'path';

/** 同梱 DB を読んでよいテスト（リポジトリ直下からの相対パス、区切りは /） */
export const BUNDLED_DB_READ_ALLOWLIST: readonly string[] = ['tests/advisory-db-invariants.test.ts'];

/** 現在の版の文字列を書いてよいテスト（v1.8.0 時点では無し） */
export const VERSION_LITERAL_ALLOWLIST: readonly string[] = [];

/** 検査しないディレクトリ（人が取得したスナップショットはテストのコードではない） */
const EXCLUDED_DIRS: readonly string[] = ['tests/fixtures/snapshots'];

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs']);

export type HygieneRule = 'bundled-advisory-db' | 'current-version-literal';

export interface HygieneViolation {
  /** リポジトリ直下からの相対パス（区切りは /） */
  file: string;
  /** 1 始まりの行番号 */
  line: number;
  rule: HygieneRule;
  /** 該当した文字列 */
  match: string;
}

export interface HygieneScanOptions {
  /** リポジトリ直下（またはそれに見立てた一時ディレクトリ）。この下の tests/ を検査する */
  rootDir: string;
  /** 現在の版（package.json の version） */
  version: string;
  bundledDbAllowlist?: readonly string[];
  versionAllowlist?: readonly string[];
}

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/** rootDir/tests 以下のテストのソースファイル（.ts / .mjs など）を、rootDir からの相対パスで返す */
export function listTestSourceFiles(rootDir: string): string[] {
  const out: string[] = [];
  const walk = (absDir: string): void => {
    for (const ent of fs.readdirSync(absDir, { withFileTypes: true })) {
      const abs = path.join(absDir, ent.name);
      const rel = toPosix(path.relative(rootDir, abs));
      if (ent.isDirectory()) {
        if (ent.name === 'node_modules') continue;
        if (EXCLUDED_DIRS.some((d) => rel === d || rel.startsWith(`${d}/`))) continue;
        walk(abs);
      } else if (ent.isFile() && SOURCE_EXTENSIONS.has(path.extname(ent.name))) {
        out.push(rel);
      }
    }
  };
  const testsDir = path.join(rootDir, 'tests');
  if (fs.existsSync(testsDir)) walk(testsDir);
  return out.sort();
}

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split('\n').length;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// 同梱 DB のファイル名（固定 DB の advisory-db.fixture.json は該当しない）
const DB_NAME = 'advisory-db\\.json';
// （この節のコメントは、自分自身が検査に引っかからないよう、ファイル名を引用符で囲まずに書く）
const BUNDLED_DB_READ_PATTERNS: readonly RegExp[] = [
  // 静的 import / export … from で、指定子が …/advisory-db.json のもの
  new RegExp(`\\bfrom\\s*['"\`][^'"\`\\n]*${DB_NAME}['"\`]`, 'g'),
  // 動的 import(…) / require(…) / 副作用 import で、指定子が …/advisory-db.json のもの
  new RegExp(`\\b(?:import|require)\\s*\\(?\\s*['"\`][^'"\`\\n]*${DB_NAME}['"\`]`, 'g'),
  // path.join(root, 'src', 'detection', <ファイル名だけの文字列>) のように、ファイル名だけの文字列を部品として使う
  new RegExp(`['"\`]${DB_NAME}['"\`]`, 'g'),
  // fs.readFileSync / new URL / path.join・resolve などの呼び出しの引数に、…/advisory-db.json の文字列がある（引数が複数行でもよい）
  new RegExp(
    `\\b(?:readFileSync|readFile|readJson|readJSON|createReadStream|openSync|URL|join|resolve)\\s*\\([^;]*?['"\`][^'"\`\\n]*${DB_NAME}['"\`]`,
    'g'
  ),
];

/** ソースの中で同梱 DB を読んでいる箇所を返す（行番号と該当文字列） */
export function findBundledAdvisoryDbReads(source: string): Array<{ line: number; match: string }> {
  const hits = new Map<number, string>();
  for (const re of BUNDLED_DB_READ_PATTERNS) {
    re.lastIndex = 0;
    for (const m of source.matchAll(re)) {
      // 一致の終わり（＝ファイル名の位置）の行を報告する
      const end = (m.index ?? 0) + m[0].length;
      const line = lineOf(source, end);
      if (!hits.has(line)) hits.set(line, m[0].slice(-120));
    }
  }
  return [...hits.entries()].sort((a, b) => a[0] - b[0]).map(([line, match]) => ({ line, match }));
}

/**
 * ソースの中で、指定した版の文字列を直接書いている箇所を返す。
 * - 引用符で囲まれた文字列で、中身が「版」「v版」、またはそれに 4 つ目の数字が付いたもの（例: '1.2.3'、"v1.2.3"、`1.2.3.4`）
 * - 正規表現などでエスケープした形（例: 1\.2\.3）
 * describe の題名やコメントの中の言及（例: 'v1.2.3 T01: …'）は対象にしない。
 */
export function findVersionLiterals(source: string, version: string): Array<{ line: number; match: string }> {
  const plain = escapeRegExp(version);
  const escapedForm = version.split('.').map(escapeRegExp).join('\\\\\\.');
  const patterns = [
    new RegExp(`(['"\`])v?${plain}(?:\\.\\d+)?\\1`, 'g'),
    new RegExp(`(?<![\\d.])${escapedForm}(?!\\d)`, 'g'),
  ];
  const hits = new Map<number, string>();
  for (const re of patterns) {
    for (const m of source.matchAll(re)) {
      const line = lineOf(source, m.index ?? 0);
      if (!hits.has(line)) hits.set(line, m[0]);
    }
  }
  return [...hits.entries()].sort((a, b) => a[0] - b[0]).map(([line, match]) => ({ line, match }));
}

/** rootDir/tests を検査し、違反を返す（違反が無ければ空配列） */
export function scanTestHygiene(options: HygieneScanOptions): HygieneViolation[] {
  const dbAllow = new Set(options.bundledDbAllowlist ?? BUNDLED_DB_READ_ALLOWLIST);
  const verAllow = new Set(options.versionAllowlist ?? VERSION_LITERAL_ALLOWLIST);
  const violations: HygieneViolation[] = [];
  for (const rel of listTestSourceFiles(options.rootDir)) {
    const source = fs.readFileSync(path.join(options.rootDir, rel), 'utf-8');
    if (!dbAllow.has(rel)) {
      for (const hit of findBundledAdvisoryDbReads(source)) {
        violations.push({ file: rel, line: hit.line, rule: 'bundled-advisory-db', match: hit.match });
      }
    }
    if (!verAllow.has(rel)) {
      for (const hit of findVersionLiterals(source, options.version)) {
        violations.push({ file: rel, line: hit.line, rule: 'current-version-literal', match: hit.match });
      }
    }
  }
  return violations;
}

/** 失敗時のメッセージ用 */
export function formatViolations(violations: readonly HygieneViolation[]): string {
  return violations.map((v) => `${v.file}:${v.line} [${v.rule}] ${v.match}`).join('\n');
}
