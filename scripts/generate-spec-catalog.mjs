/**
 * Web Technology & Security Inspector
 * 検出仕様書カタログ自動生成スクリプト (scripts/generate-spec-catalog.mjs)
 * 
 * src/detection/rules/*.json から全技術のシグナル・重み・連動先を抽出し、
 * docs/DETECTION_SPECIFICATION.md のカタログ表（第3節）を自動同期・更新します。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const RULES_DIR = path.join(ROOT_DIR, 'src', 'detection', 'rules');
const SPEC_FILE = path.join(ROOT_DIR, 'docs', 'DETECTION_SPECIFICATION.md');

function loadJson(filename) {
  const filePath = path.join(RULES_DIR, filename);
  return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
}

const serverRules = loadJson('server.json');
const languageRules = loadJson('language.json');
const backendRules = loadJson('backend.json');
const cmsRules = loadJson('cms.json');
const frontendRules = loadJson('frontend.json');
const servicesRules = loadJson('services.json');
const cdnWafRules = loadJson('cdn-waf.json');

const allRules = [
  ...serverRules,
  ...languageRules,
  ...backendRules,
  ...cmsRules,
  ...frontendRules,
  ...servicesRules,
  ...cdnWafRules,
];

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

function formatVersionExtraction(rule) {
  const vSignal = rule.signals.find((s) => s.versionRegex);
  if (vSignal) {
    return escapePipe(vSignal.versionRegex) + ' より抽出';
  }
  if (rule.id === 'wordpress') {
    return '`WordPress\\s+([0-9.]+)` またはコアアセットの `?ver=([0-9.]+)`';
  }
  return '-';
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

function main() {
  console.log(`[generate-spec-catalog] 全${allRules.length}技術のルール定義からカタログを生成中...`);

  const specContent = fs.readFileSync(SPEC_FILE, 'utf-8');

  const startMarker = '## 3. 全調査対象技術 判定基準カタログ';
  const endMarker = '## 4. Implication Engine（連動推論）連動マトリクス';

  const startIndex = specContent.indexOf(startMarker);
  const endIndex = specContent.indexOf(endMarker);

  if (startIndex === -1 || endIndex === -1) {
    throw new Error('仕様書内のマーカーが見つかりませんでした。');
  }

  const catalogMarkdown = `${startMarker} (計${allRules.length}技術)

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

  const newSpecContent = specContent.slice(0, startIndex) + catalogMarkdown + specContent.slice(endIndex);

  fs.writeFileSync(SPEC_FILE, newSpecContent, 'utf-8');
  console.log(`[generate-spec-catalog] 仕様書カタログを正常に更新完了: ${SPEC_FILE}`);
}

main();
