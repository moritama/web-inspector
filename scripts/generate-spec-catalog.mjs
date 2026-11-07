/**
 * Web Technology & Security Inspector
 * 検出仕様書カタログ・READMEカバレッジ表・DOMセレクタ・PSL定義 自動生成スクリプト
 * (scripts/generate-spec-catalog.mjs)
 *
 * - src/detection/rules/*.json から全技術のシグナル・重み・連動先を抽出し、
 *   docs/DETECTION_SPECIFICATION.md のカタログ表（第3節）を自動同期・更新します。
 * - README.md の「対応技術スタック & 診断カバレッジ (Coverage)」表を自動生成します (DOC-07)。
 * - src/content/dom-selectors.generated.ts を自動生成します (DOC-01)。
 * - src/security/psl-rules.generated.ts を自動生成します (DOC-12)。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeGeneratedPslModule } from './advisories/lib/psl.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const ROOT_DIR = path.resolve(__dirname, '..');
export const RULES_DIR = path.join(ROOT_DIR, 'src', 'detection', 'rules');
export const SPEC_FILE = path.join(ROOT_DIR, 'docs', 'DETECTION_SPECIFICATION.md');
export const README_FILE = path.join(ROOT_DIR, 'README.md');
export const CATALOG_FILE = path.join(ROOT_DIR, 'data', 'advisories', 'catalog.json');

/**
 * content-script.ts (MAIN world ブリッジ) で実行時バージョン取得に対応している技術ID一覧
 */
export const RUNTIME_VERSION_TECH_IDS = new Set([
  'jquery',
  'bootstrap',
  'vue',
  'lodash',
  'moment',
  'angularjs',
]);

function loadRuleJson(filename) {
  const filePath = path.join(RULES_DIR, filename);
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

export const serverRules = loadRuleJson('server.json');
export const languageRules = loadRuleJson('language.json');
export const backendRules = loadRuleJson('backend.json');
export const cmsRules = loadRuleJson('cms.json');
export const frontendRules = loadRuleJson('frontend.json');
export const servicesRules = loadRuleJson('services.json');
export const cdnWafRules = loadRuleJson('cdn-waf.json');

export const RULE_GROUPS = [
  { label: 'Webサーバー', rules: serverRules },
  { label: 'プログラミング言語・ランタイム', rules: languageRules },
  { label: 'バックエンドFW', rules: backendRules },
  { label: 'CMS', rules: cmsRules },
  { label: 'フロントエンドFW / UI', rules: frontendRules },
  { label: 'クラウド・外部サービス', rules: servicesRules },
  { label: 'CDN / WAF', rules: cdnWafRules },
];

export const allRules = RULE_GROUPS.flatMap((g) => g.rules);

export function loadAdvisoryCatalog() {
  return JSON.parse(fs.readFileSync(CATALOG_FILE, 'utf-8'));
}

/**
 * 対象技術がバージョン特定手段（versionRegex または実行時バージョン取得）を持つか判定する (DOC-07)
 */
export function hasVersionExtraction(rule) {
  if (!rule || !Array.isArray(rule.signals)) return false;
  if (rule.signals.some((s) => Boolean(s.versionRegex))) return true;
  if (RUNTIME_VERSION_TECH_IDS.has(rule.id)) return true;
  return false;
}

function escapePipe(str) {
  if (!str) return '-';
  return str.replace(/\|/g, '\\|').replace(/\]\(/g, '\\]\\(');
}

function formatSignals(signals) {
  return signals.map((s) => `\`${s.type}\`: \`${s.target || '-'}\``).join('<br>');
}

function formatPatterns(signals) {
  return signals
    .map((s) => {
      const p = s.pattern || '存在一致 (`.*`)';
      return escapePipe(p);
    })
    .join('<br>');
}

function formatWeights(signals) {
  return signals.map((s) => s.weight).join('<br>');
}

function formatImplies(rule) {
  if (!rule.implies || rule.implies.length === 0) return '-';
  return rule.implies
    .map((imp) => {
      const id = typeof imp === 'string' ? imp : imp.id;
      const status = typeof imp === 'object' && imp.runtimeStatus ? ` (\`${imp.runtimeStatus}\`)` : '';
      const matched = allRules.find((r) => r.id === id);
      const name = matched ? matched.name : id;
      return `$\\rightarrow$ **${name}**${status}`;
    })
    .join('<br>');
}

function generateTable(rules, includeImplies = false, includeRuntime = false) {
  let header = '| 技術ID | 技術名 | 判定シグナル | 照合パターン / 正規表現 | 重み |';
  let divider = '| :--- | :--- | :--- | :--- | :--- |';

  if (includeImplies) {
    header += ' 連動推論先 |';
    divider += ' :--- |';
  }
  if (includeRuntime) {
    header += ' 連動推論先 |';
    divider += ' :--- |';
  }

  const rows = rules.map((r) => {
    let row = `| \`${r.id}\` | **${r.name}** | ${formatSignals(r.signals)} | ${formatPatterns(r.signals)} | ${formatWeights(r.signals)} |`;
    if (includeImplies) {
      row += ` ${formatImplies(r)} |`;
    }
    return row;
  });

  return [header, divider, ...rows].join('\n');
}

function generateServicesTable(rules) {
  const header = '| 技術ID | 技術名 | カテゴリ | 判定シグナル | 照合パターン / 正規表現 | 重み |';
  const divider = '| :--- | :--- | :--- | :--- | :--- | :--- |';

  const rows = rules.map((r) => {
    return `| \`${r.id}\` | **${r.name}** | \`${r.category}\` | ${formatSignals(r.signals)} | ${formatPatterns(r.signals)} | ${formatWeights(r.signals)} |`;
  });

  return [header, divider, ...rows].join('\n');
}

function summarizeRuleSignalsForReadme(rule) {
  const seen = new Set();
  const parts = [];
  for (const s of rule.signals || []) {
    const label = s.target ? `${s.type} (${s.target})` : s.type;
    if (!seen.has(label)) {
      seen.add(label);
      parts.push(escapePipe(label));
    }
  }
  if (RUNTIME_VERSION_TECH_IDS.has(rule.id)) {
    parts.push('実行時バージョン取得 (MAIN world)');
  }
  return parts.join(', ');
}

/**
 * README.md の「対応技術スタック & 診断カバレッジ (Coverage)」セクションを生成する (DOC-07)
 */
export function generateReadmeCoverageSection(groups = RULE_GROUPS, catalog = loadAdvisoryCatalog()) {
  const totalCount = groups.reduce((acc, g) => acc + g.rules.length, 0);
  const rows = [];

  for (const group of groups) {
    group.rules.forEach((rule, idx) => {
      const groupCol = idx === 0 ? `**${group.label}**` : '';
      const verMark = hasVersionExtraction(rule) ? '✅' : '-';
      const prod = catalog?.products?.[rule.id];
      const eolMark = prod?.eol ? '✅' : '-';
      const cveMark = prod?.osv || prod?.nvd ? '✅' : '-';
      const nameCell =
        eolMark === '✅' || cveMark === '✅'
          ? `**${rule.name}** (\`${rule.id}\`)`
          : `${rule.name} (\`${rule.id}\`)`;
      const methodCell = summarizeRuleSignalsForReadme(rule);
      rows.push(`| ${groupCol} | ${nameCell} | ${verMark} | ${eolMark} | ${cveMark} | ${methodCell} |`);
    });
  }

  return `## 対応技術スタック & 診断カバレッジ (Coverage)

本拡張機能が検出・診断に対応している全 ${totalCount} 技術の一覧です（\`npm run spec:generate\` により \`src/detection/rules/*.json\` および \`data/advisories/catalog.json\` から自動生成）。  
※「バージョン特定」はシグナル定義に \`versionRegex\` を持つ技術、またはページ実行時（MAIN world）からバージョンを取得できる技術のみ \`✅\` としています。  
※「EOL判定」「既知脆弱性 (CVE)」が \`✅\` の技術は、外部送信を行わず拡張機能内蔵のオフライン脆弱性データベース（\`advisory-db.json\`）と完全ローカルで照合されます。

| 分類 | 対象技術名 | バージョン特定 | EOL判定 | 既知脆弱性 (CVE) | 主な検出手法 |
|---|---|:---:|:---:|:---:|---|
${rows.join('\n')}

`;
}

/**
 * docs/DETECTION_SPECIFICATION.md の第3節カタログMarkdownを生成する
 */
export function generateSpecCatalogSection() {
  const startMarker = '## 3. 全調査対象技術 判定基準カタログ';
  return `${startMarker} (計${allRules.length}技術)

> [!NOTE]
> **カタログの自動整合保証:**  
> 本カタログ（第3節）は \`src/detection/rules/*.json\` のルール定義から直接自動生成（\`npm run spec:generate\`）されており、自動整合テスト (\`tests/spec-integrity.test.ts\`) によって100%の一致が保証されています。

### 3.1 Webサーバー (\`web-server\`)
Webサーバーは主にHTTPレスポンスの \`Server\` ヘッダーを主たるエビデンスとして判定します。

${generateTable(serverRules)}

> [!TIP]
> **CDN・リバースプロキシによるServerヘッダーの書き換えについて:**  
> Cloudflare 等のCDNを利用している場合、オリジンの \`Server: Apache\` は \`Server: cloudflare\` に書き換えられます。一方、Amazon CloudFront 等ではオリジンのヘッダーがそのまま通過します。

---

### 3.2 プログラミング言語・ランタイム (\`programming-language\`)

${generateTable(languageRules)}

> [!NOTE]
> **Node.js のバージョン観測とCVE/EOL照合について:**  
> Node.js のバージョンは通常本番環境のHTTPヘッダーには出力されないため、外部受動調査では「バージョン不明」となります。そのため、Node.js 向けのEOL/CVE照合は誤報防止の安全設計により原則として発火しません。

---

### 3.3 バックエンドフレームワーク (\`programming-language\` / \`framework\`)

${generateTable(backendRules, true)}

---

### 3.4 CMS（コンテンツマネジメントシステム） (\`cms\`)

${generateTable(cmsRules, true)}

---

### 3.5 フロントエンドフレームワーク・UIライブラリ (\`js-framework\`, \`js-css-library\`)

${generateTable(frontendRules, true)}

---

### 3.6 クラウドホスティング・外部サービス・解析・セキュリティ (\`hosting-cloud\`, \`analytics-tracking\`, \`security-service\`)

${generateServicesTable(servicesRules)}

---

### 3.7 CDN / WAF (\`cdn-waf\`)

${generateTable(cdnWafRules)}

---

`;
}

function writeFileIfChanged(filePath, newContent) {
  const current = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf-8') : null;
  if (current !== newContent) {
    fs.writeFileSync(filePath, newContent, 'utf-8');
    return true;
  }
  return false;
}

export function generateDomSelectorsFile() {
  const domSelectors = new Set();

  for (const rule of allRules) {
    for (const signal of rule.signals) {
      if (signal.type === 'dom') {
        if (signal.target === 'title') continue;
        const targets = signal.target.split(',').map((t) => t.trim()).filter(Boolean);
        for (const t of targets) {
          domSelectors.add(t);
        }
      }
    }
  }

  const sortedSelectors = Array.from(domSelectors).sort();

  const fileContent = `/**
 * Web Technology & Security Inspector
 * 自動生成ファイル: DOMシグナル探査用セレクタ一覧 (src/content/dom-selectors.generated.ts)
 * 
 * scripts/generate-spec-catalog.mjs により自動生成されます。手動で編集しないでください。
 * (npm run spec:generate で再生成されます)
 */

export const DOM_MARKER_SELECTORS: string[] = ${JSON.stringify(sortedSelectors, null, 2)};
`;

  const outputPath = path.join(ROOT_DIR, 'src', 'content', 'dom-selectors.generated.ts');
  writeFileIfChanged(outputPath, fileContent);
  console.log(`[generate-spec-catalog] DOMセレクタ一覧を正常に生成完了 (${sortedSelectors.length}件): ${outputPath}`);
}

export function updateReadmeCoverage() {
  const readmeContent = fs.readFileSync(README_FILE, 'utf-8');
  const startMarker = '## 対応技術スタック & 診断カバレッジ (Coverage)';
  const endMarker = '## システムアーキテクチャ';

  const startIndex = readmeContent.indexOf(startMarker);
  const endIndex = readmeContent.indexOf(endMarker);

  if (startIndex === -1 || endIndex === -1) {
    throw new Error('README.md 内のカバレッジ表マーカーが見つかりませんでした。');
  }

  const coverageMarkdown = generateReadmeCoverageSection();
  const newReadmeContent =
    readmeContent.slice(0, startIndex) + coverageMarkdown + readmeContent.slice(endIndex);

  writeFileIfChanged(README_FILE, newReadmeContent);
  console.log(`[generate-spec-catalog] READMEカバレッジ表を正常に更新完了: ${README_FILE}`);
}

export function main() {
  console.log(`[generate-spec-catalog] 全${allRules.length}技術のルール定義からカタログを生成中...`);

  // 1. 仕様書カタログMarkdownの更新
  const specContent = fs.readFileSync(SPEC_FILE, 'utf-8');

  const startMarker = '## 3. 全調査対象技術 判定基準カタログ';
  const endMarker = '## 4. Implication Engine（連動推論）連動マトリクス';

  const startIndex = specContent.indexOf(startMarker);
  const endIndex = specContent.indexOf(endMarker);

  if (startIndex === -1 || endIndex === -1) {
    throw new Error('仕様書内のマーカーが見つかりませんでした。');
  }

  const catalogMarkdown = generateSpecCatalogSection();
  const newSpecContent = specContent.slice(0, startIndex) + catalogMarkdown + specContent.slice(endIndex);

  writeFileIfChanged(SPEC_FILE, newSpecContent);
  console.log(`[generate-spec-catalog] 仕様書カタログを正常に更新完了: ${SPEC_FILE}`);

  // 2. README.md カバレッジ表の自動生成 (T13 / DOC-07)
  updateReadmeCoverage();

  // 3. content-script専用のDOMセレクタ定義の生成 (T06 / DOC-01)
  generateDomSelectorsFile();

  // 4. PSL ルール定義の自動生成 (T13 / DOC-12)
  const pslRes = writeGeneratedPslModule();
  console.log(
    `[generate-spec-catalog] PSLルール定義を正常に確認完了 (source: ${pslRes.source}, suffixes: ${pslRes.suffixes.length}): ${pslRes.outputPath}`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
