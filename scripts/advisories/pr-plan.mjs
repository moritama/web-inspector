#!/usr/bin/env node
/**
 * Web Technology & Security Inspector
 * 脆弱性DB自動更新ワークフローのPR作成・自動マージ計画 (scripts/advisories/pr-plan.mjs)
 *
 * diff-db の分類結果 (none / minor / major)、テストの成否、失敗したテスト名、
 * リポジトリ変数 ADVISORY_AUTO_MERGE、GitHub App トークンの有無から、
 * PR の作成有無・付与ラベル・本文・自動マージ可否・ジョブ最終成否を決定的に算出する。
 *
 * 使い方:
 *   node scripts/advisories/pr-plan.mjs \
 *     --classification minor \
 *     --version 1.7.0.1 \
 *     --tests-passed false \
 *     --auto-merge true \
 *     --has-app-token true \
 *     --diff-md db-diff.md \
 *     --test-log test-output.log \
 *     --out-body pr-body.md \
 *     --out-json pr-plan.json
 */

import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

/** テスト失敗時に付与するラベル名 */
export const FAILING_TESTS_LABEL = 'db:tests-failing';

/**
 * 文字列から ANSI エスケープシーケンスを除去する
 *
 * @param {string} text - 入力文字列
 * @returns {string} ANSI エスケープ除去後の文字列
 */
export function stripAnsi(text) {
  return String(text || '').replace(/\x1B\[[0-9;]*[A-Za-z]/g, '');
}

/**
 * Vitest JSON レポート、テスト標準出力ログ、または配列から失敗したテスト名を抽出する
 *
 * @param {object | string | string[] | null | undefined} input - テスト結果入力
 * @returns {string[]} 重複排除済みの失敗テスト名一覧
 */
export function extractFailedTests(input) {
  if (!input) return [];

  // 配列が渡された場合は文字列として正規化して返す
  if (Array.isArray(input)) {
    return Array.from(new Set(input.map((x) => String(x).trim()).filter(Boolean)));
  }

  // Vitest JSON レポートオブジェクトの場合
  if (typeof input === 'object') {
    const failed = [];
    for (const suite of input.testResults || []) {
      const assertions = suite.assertionResults || [];
      let suiteAdded = false;
      for (const a of assertions) {
        if (a.status === 'failed') {
          failed.push((a.fullName || a.title || '').trim());
          suiteAdded = true;
        }
      }
      if (!suiteAdded && suite.status === 'failed' && suite.name) {
        failed.push(String(suite.name).trim());
      }
    }
    return Array.from(new Set(failed.filter(Boolean)));
  }

  const raw = String(input);
  const trimmed = raw.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && Array.isArray(parsed.testResults)) {
        return extractFailedTests(parsed);
      }
    } catch {
      // JSON パース失敗時は標準出力テキストとして解析を続行
    }
  }

  const clean = stripAnsi(raw);
  const lines = clean.split(/\r?\n/);
  const failHeaderMatches = [];
  const crossMatches = [];
  const otherErrors = [];

  for (const line of lines) {
    // Vitest サマリーヘッダー: " FAIL  tests/xxx.test.ts > Suite > test name"
    const failMatch = line.match(/^\s*FAIL\s+(.+?)\s*$/);
    if (failMatch) {
      failHeaderMatches.push(failMatch[1].trim());
      continue;
    }
    // Vitest ツリー出力: "   × test name" または "   ✕ test name"
    const crossMatch = line.match(/^\s*[×✕]\s+(.+?)(?:\s+\d+\s*ms)?\s*$/);
    if (crossMatch) {
      crossMatches.push(crossMatch[1].trim());
      continue;
    }
    // TypeScript 型検査エラー
    const tsMatch = line.match(/^(.+\(\d+,\d+\):\s+error\s+TS\d+:.+)$/);
    if (tsMatch) {
      otherErrors.push(tsMatch[1].trim());
    }
  }

  if (failHeaderMatches.length > 0) {
    return Array.from(new Set(failHeaderMatches));
  }
  if (crossMatches.length > 0) {
    return Array.from(new Set(crossMatches));
  }
  if (otherErrors.length > 0) {
    return Array.from(new Set(otherErrors));
  }
  return [];
}

/**
 * 差分 Markdown にテスト失敗セクションを付加して PR 本文を生成する
 *
 * @param {string} diffMarkdown - diff-db が生成した Markdown
 * @param {object} [options] - オプション
 * @param {boolean} [options.testsPassed=true] - テストが成功したか
 * @param {string[]} [options.failedTests=[]] - 失敗したテスト名一覧
 * @returns {string} PR 本文 Markdown
 */
export function renderPrBody(diffMarkdown, { testsPassed = true, failedTests = [] } = {}) {
  const base = String(diffMarkdown || '').trimEnd();
  if (testsPassed && (!failedTests || failedTests.length === 0)) {
    return base ? `${base}\n` : '';
  }

  const lines = [];
  if (base) {
    lines.push(base, '');
  }
  lines.push(`### ❌ 失敗したテスト (\`${FAILING_TESTS_LABEL}\`)`);
  lines.push('');
  lines.push('`npm test` または `npm run build` が失敗したため、自動マージは抑止されています。内容を確認してください。');
  lines.push('');
  if (failedTests && failedTests.length > 0) {
    for (const name of failedTests.slice(0, 100)) {
      lines.push(`- \`${String(name).replace(/`/g, "'")}\``);
    }
    if (failedTests.length > 100) {
      lines.push(`- … ほか ${failedTests.length - 100} 件`);
    }
  } else {
    lines.push('- (個別の失敗テスト名を特定できませんでした。Actions の実行ログを確認してください)');
  }
  return `${lines.join('\n')}\n`;
}

/**
 * 真偽値または文字列フラグを正規化する
 *
 * @param {unknown} value - 入力値
 * @param {boolean} defaultValue - 未定義時の既定値
 * @returns {boolean} 正規化された真偽値
 */
function parseBooleanFlag(value, defaultValue) {
  if (value === undefined) return defaultValue;
  if (typeof value === 'boolean') return value;
  if (value === null) return false;
  const s = String(value).trim().toLowerCase();
  if (s === '' || s === 'false' || s === '0' || s === 'no') return false;
  if (s === 'true' || s === '1' || s === 'yes') return true;
  return Boolean(value);
}

/**
 * 脆弱性DB更新 PR の作成・ラベル・自動マージ計画を算出する
 *
 * @param {object} [params] - 入力パラメータ
 * @param {'none' | 'minor' | 'major'} [params.classification='none'] - DB差分の分類
 * @param {string} [params.version=''] - 新しい manifest.version
 * @param {boolean | string} [params.testsPassed] - テストが成功したか
 * @param {boolean | string} [params.testPassed] - testsPassed の別名
 * @param {boolean | string} [params.testSuccess] - testsPassed の別名
 * @param {string[]} [params.failedTests=[]] - 失敗したテスト名一覧
 * @param {string} [params.testOutput=''] - テスト標準出力ログ
 * @param {object | null} [params.vitestReport=null] - Vitest JSON レポート
 * @param {boolean | string} [params.autoMerge=false] - ADVISORY_AUTO_MERGE 設定値
 * @param {boolean | string} [params.autoMergeEnabled] - autoMerge の別名
 * @param {boolean | string} [params.hasAppToken=true] - GitHub App トークン有無
 * @param {string} [params.appToken] - GitHub App トークン文字列 (指定時は非空で true)
 * @param {string} [params.diffMarkdown=''] - diff-db が生成した Markdown
 * @returns {object} PR 計画オブジェクト
 */
export function planPullRequest(params = {}) {
  const {
    classification = 'none',
    version = '',
    testsPassed,
    testPassed,
    testSuccess,
    failedTests = [],
    testOutput = '',
    vitestReport = null,
    autoMerge = false,
    autoMergeEnabled,
    hasAppToken,
    appToken,
    diffMarkdown = '',
  } = params;

  // 失敗したテスト名の解決
  let resolvedFailedTests = extractFailedTests(failedTests);
  if (resolvedFailedTests.length === 0 && vitestReport) {
    resolvedFailedTests = extractFailedTests(vitestReport);
  }
  if (resolvedFailedTests.length === 0 && testOutput) {
    resolvedFailedTests = extractFailedTests(testOutput);
  }

  // テスト成否の解決
  const rawPassed = testsPassed !== undefined ? testsPassed : testPassed !== undefined ? testPassed : testSuccess;
  const explicitPassed = parseBooleanFlag(rawPassed, resolvedFailedTests.length === 0);
  const isTestFailing = !explicitPassed || resolvedFailedTests.length > 0;
  const effectiveTestsPassed = !isTestFailing;

  const isAutoMergeRequested = parseBooleanFlag(
    autoMergeEnabled !== undefined ? autoMergeEnabled : autoMerge,
    false
  );
  const isAppTokenAvailable =
    appToken !== undefined
      ? Boolean(String(appToken).trim())
      : parseBooleanFlag(hasAppToken, true);

  if (classification === 'none') {
    return {
      classification: 'none',
      version,
      shouldCreatePr: false,
      createPr: false,
      title: '',
      labels: [],
      removeLabels: [],
      shouldAutoMerge: false,
      autoMerge: false,
      shouldFailJob: false,
      failJob: false,
      testsPassed: effectiveTestsPassed,
      failedTests: resolvedFailedTests,
      hasAppToken: isAppTokenAvailable,
      warnings: [],
      body: String(diffMarkdown || ''),
    };
  }

  const title = `chore(advisory-db): 脆弱性DB自動更新 v${version} [${classification}]`;
  const labels = ['advisory-db', `db:${classification}`];
  const removeLabels = [classification === 'major' ? 'db:minor' : 'db:major'];

  if (isTestFailing) {
    labels.push(FAILING_TESTS_LABEL);
  } else {
    removeLabels.push(FAILING_TESTS_LABEL);
  }

  const warnings = [];
  if (!isAppTokenAvailable) {
    warnings.push(
      'GitHub App トークンが未設定のため自動マージを行いません (GITHUB_TOKEN では PR の CI やマージ後の release.yml が起動しないため)'
    );
  }

  // 自動マージ条件: minor かつ テスト合格 (db:tests-failing なし) かつ ADVISORY_AUTO_MERGE=true かつ App トークンあり
  const shouldAutoMerge =
    classification === 'minor' &&
    effectiveTestsPassed &&
    !labels.includes(FAILING_TESTS_LABEL) &&
    isAutoMergeRequested &&
    isAppTokenAvailable;

  const shouldFailJob = isTestFailing;
  const body = renderPrBody(diffMarkdown, {
    testsPassed: effectiveTestsPassed,
    failedTests: resolvedFailedTests,
  });

  return {
    classification,
    version,
    shouldCreatePr: true,
    createPr: true,
    title,
    labels,
    removeLabels,
    shouldAutoMerge,
    autoMerge: shouldAutoMerge,
    shouldFailJob,
    failJob: shouldFailJob,
    testsPassed: effectiveTestsPassed,
    failedTests: resolvedFailedTests,
    hasAppToken: isAppTokenAvailable,
    warnings,
    body,
  };
}

export { planPullRequest as buildPrPlan, planPullRequest as createPrPlan };

/**
 * CLI 引数を解析する
 *
 * @param {string[]} argv - process.argv
 * @returns {Record<string, string | boolean>} 解析されたオプション
 */
function parseArgs(argv) {
  const a = {};
  for (let i = 2; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      a[argv[i].slice(2)] = argv[i + 1]?.startsWith('--') ? true : argv[++i];
    }
  }
  return a;
}

function main() {
  const args = parseArgs(process.argv);
  const classification = args.classification || process.env.CLASSIFICATION || 'none';
  const version = args.version || process.env.VERSION || '';
  const testsPassed = args['tests-passed'] ?? process.env.TESTS_PASSED ?? 'true';
  const autoMerge = args['auto-merge'] ?? process.env.AUTO_MERGE ?? 'false';
  const hasAppToken = args['has-app-token'] ?? process.env.HAS_APP_TOKEN ?? 'true';

  const diffMdPath = args['diff-md'];
  const testLogPath = args['test-log'];
  const vitestJsonPath = args['vitest-json'];

  const diffMarkdown = diffMdPath && fs.existsSync(diffMdPath) ? fs.readFileSync(diffMdPath, 'utf-8') : '';
  const testOutput = testLogPath && fs.existsSync(testLogPath) ? fs.readFileSync(testLogPath, 'utf-8') : '';
  const vitestReport =
    vitestJsonPath && fs.existsSync(vitestJsonPath)
      ? JSON.parse(fs.readFileSync(vitestJsonPath, 'utf-8'))
      : null;

  const plan = planPullRequest({
    classification,
    version,
    testsPassed,
    autoMerge,
    hasAppToken,
    diffMarkdown,
    testOutput,
    vitestReport,
  });

  for (const w of plan.warnings) {
    console.log(`::warning::${w}`);
  }

  if (args['out-body']) {
    fs.writeFileSync(args['out-body'], plan.body, 'utf-8');
  }
  if (args['out-json']) {
    fs.writeFileSync(args['out-json'], `${JSON.stringify(plan, null, 2)}\n`, 'utf-8');
  }

  if (process.env.GITHUB_OUTPUT) {
    const outLines = [
      `should_create_pr=${plan.shouldCreatePr}`,
      `should_auto_merge=${plan.shouldAutoMerge}`,
      `should_fail_job=${plan.shouldFailJob}`,
      `tests_passed=${plan.testsPassed}`,
      `has_app_token=${plan.hasAppToken}`,
      `title=${plan.title}`,
      `labels=${plan.labels.join(',')}`,
      `remove_labels=${plan.removeLabels.join(',')}`,
    ];
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${outLines.join('\n')}\n`);
  }

  console.error(
    `[pr-plan] classification=${plan.classification} shouldCreatePr=${plan.shouldCreatePr} labels=${plan.labels.join(',')} shouldAutoMerge=${plan.shouldAutoMerge} shouldFailJob=${plan.shouldFailJob}`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
