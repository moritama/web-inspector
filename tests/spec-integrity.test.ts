/**
 * Web Technology & Security Inspector
 * 仕様書・ルール整合性自動検証テスト (tests/spec-integrity.test.ts)
 * 
 * docs/DETECTION_SPECIFICATION.md と src/detection/rules/*.json の完全一致を検証し、
 * 仕様書と実装・定義の乖離（取りこぼし、誤記、未記載）を恒久的に防止します。
 */

import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ALL_TECHNOLOGY_RULES, RULES_VERSION, TechnologyRule } from '../src/detection/rules';

describe('仕様書・ルール定義の整合性テスト (Specification Integrity)', () => {
  const specPath = path.resolve(__dirname, '../docs/DETECTION_SPECIFICATION.md');
  const specContent = fs.readFileSync(specPath, 'utf-8');

  // 仕様書のMarkdownテーブル（第1列が `tech_id`）から技術IDを抽出
  const specLines = specContent.split('\n');
  const specTechIds: string[] = [];
  const specNameMap = new Map<string, string>();

  for (const line of specLines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('| `') && !trimmed.startsWith('| 技術ID')) {
      const cols = trimmed.split('|').map((c) => c.trim());
      // cols[0] is "", cols[1] is `id`, cols[2] is **Name**
      if (cols.length > 2 && cols[1].startsWith('`') && cols[1].endsWith('`')) {
        const id = cols[1].replace(/`/g, '');
        specTechIds.push(id);
        const name = cols[2].replace(/\*\*/g, '').trim();
        specNameMap.set(id, name);
      }
    }
  }

  const allRules: TechnologyRule[] = ALL_TECHNOLOGY_RULES;
  const ruleIds = allRules.map((r) => r.id);
  const ruleIdSet = new Set(ruleIds);

  it('ルール定義と仕様書カタログの登録技術数が完全に一致すること (全75技術)', () => {
    expect(allRules.length).toBe(75);
    expect(specTechIds.length).toBe(75);
    expect(new Set(specTechIds).size).toBe(75);
  });

  it('ルール定義(rules/*.json)に存在する全技術IDが仕様書に含まれていること', () => {
    const specIdSet = new Set(specTechIds);
    const missingInSpec = ruleIds.filter((id) => !specIdSet.has(id));
    expect(missingInSpec).toEqual([]);
  });

  it('仕様書に記載されている全技術IDがルール定義に実在すること', () => {
    const missingInRules = specTechIds.filter((id) => !ruleIdSet.has(id));
    expect(missingInRules).toEqual([]);
  });

  it('各技術の名称(name)が仕様書と例外なく完全に一致していること', () => {
    for (const rule of allRules) {
      const specName = specNameMap.get(rule.id);
      expect(specName).toBeDefined();
      if (specName) {
        expect(specName.toLowerCase()).toBe(rule.name.toLowerCase());
      }
    }
  });

  it('各技術のシグナルの重み(weight)が仕様書の記載と完全に一致していること', () => {
    // 仕様書の各行から重みリストを抽出
    const specWeightMap = new Map<string, number[]>();

    for (const line of specLines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('| `') && !trimmed.startsWith('| 技術ID')) {
        const cols = trimmed.split('|').map((c) => c.trim());
        if (cols.length > 2 && cols[1].startsWith('`') && cols[1].endsWith('`')) {
          const id = cols[1].replace(/`/g, '');
          // 重み列を探す (数値<br>数値 のパターン)
          for (let i = 3; i < cols.length; i++) {
            const matches = cols[i].match(/\b\d{2,3}\b/g);
            if (matches && matches.length > 0) {
              const rule = allRules.find((r) => r.id === id);
              if (rule && matches.length === rule.signals.length) {
                specWeightMap.set(id, matches.map(Number));
                break;
              }
            }
          }
        }
      }
    }

    for (const rule of allRules) {
      const expectedWeights = rule.signals.map((s) => s.weight);
      const specWeights = specWeightMap.get(rule.id);
      expect(
        specWeights,
        `技術「${rule.id}」の重み列が仕様書から取得できませんでした`
      ).toBeDefined();
      expect(
        specWeights,
        `技術「${rule.id}」の重みが仕様書と一致しません (仕様: ${specWeights}, ルール: ${expectedWeights})`
      ).toEqual(expectedWeights);
    }
  });

  it('連動推論先(implies)に指定されている技術IDがすべて実在する技術IDであること', () => {
    for (const rule of allRules) {
      if (rule.implies && rule.implies.length > 0) {
        for (const imp of rule.implies) {
          const targetId = typeof imp === 'string' ? imp : imp.id;
          expect(
            ruleIdSet.has(targetId),
            `技術「${rule.id}」の連動先「${targetId}」がルール定義に存在しません`
          ).toBe(true);
        }
      }
    }
  });

  it('package.json, manifest.json, 各HTML, READMEのバージョン表記が完全に一致していること', () => {
    const rootDir = path.resolve(__dirname, '..');
    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf-8'));
    const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, 'public', 'manifest.json'), 'utf-8'));
    const version = pkg.version;

    // 1. manifest.json との一致 (DBのみ更新リリースでは第4要素 = DBリビジョンが付与される: 例 1.6.5.2)
    const [mBase, mRev] = [manifest.version.split('.').slice(0, 3).join('.'), manifest.version.split('.')[3]];
    expect(mBase).toBe(version);
    if (mRev !== undefined) expect(mRev).toMatch(/^\d+$/);

    // 2. HTMLファイルのバージョンバッジ表示一致（ルート直下の popup.html / dashboard.html に一本化）
    const htmlFiles = [
      path.join(rootDir, 'popup.html'),
      path.join(rootDir, 'dashboard.html'),
    ];

    for (const htmlPath of htmlFiles) {
      expect(fs.existsSync(htmlPath), `${htmlPath} が存在しません`).toBe(true);
      const content = fs.readFileSync(htmlPath, 'utf-8');
      expect(
        content.includes(`v${version}`),
        `${htmlPath} にバージョン "v${version}" が含まれていません`
      ).toBe(true);
    }

    // 3. README.md のバッジ一致
    const readmeContent = fs.readFileSync(path.join(rootDir, 'README.md'), 'utf-8');
    expect(
      readmeContent.includes(`version-${version}-blue.svg`),
      `README.md にバージョンバッジ "version-${version}-blue.svg" が含まれていません`
    ).toBe(true);
  });

  it('自動生成された DOM セレクタ一覧 (dom-selectors.generated.ts) がルール定義と完全に一致していること (T06 / DOC-01)', () => {
    const rootDir = path.resolve(__dirname, '..');
    const genFilePath = path.join(rootDir, 'src', 'content', 'dom-selectors.generated.ts');
    expect(fs.existsSync(genFilePath), `${genFilePath} が存在しません`).toBe(true);

    const expectedSet = new Set<string>();
    for (const rule of allRules) {
      for (const sig of rule.signals) {
        if (sig.type === 'dom') {
          if (sig.target === 'title') continue;
          const parts = sig.target.split(',').map((s) => s.trim()).filter(Boolean);
          for (const p of parts) {
            expectedSet.add(p);
          }
        }
      }
    }
    const expectedSorted = Array.from(expectedSet).sort();

    const genContent = fs.readFileSync(genFilePath, 'utf-8');
    const match = genContent.match(/export const DOM_MARKER_SELECTORS:\s*string\[\]\s*=\s*(\[[\s\S]*?\]);/);
    expect(match, 'DOM_MARKER_SELECTORS の定義が見つかりませんでした').toBeDefined();
    if (match) {
      const parsedSelectors = JSON.parse(match[1]) as string[];
      expect(parsedSelectors).toEqual(expectedSorted);
    }
  });

  it('仕様書 §4 の連動推論図・表と rules/*.json の implies 定義（relation, runtimeStatus, confidenceFactor）が完全に一致していること (T09 / DOC-05)', () => {
    const ruleByName = new Map<string, TechnologyRule>();
    const ruleById = new Map<string, TechnologyRule>();
    for (const r of allRules) {
      ruleByName.set(r.name, r);
      ruleById.set(r.id, r);
    }

    // 1. rules/*.json から全 implies エッジを抽出
    interface ImpliesEdge {
      sourceId: string;
      sourceName: string;
      targetId: string;
      targetName: string;
      relation: string;
      runtimeStatus: string;
      confidenceFactor: number;
    }

    const ruleEdges: ImpliesEdge[] = [];
    for (const rule of allRules) {
      if (!rule.implies || rule.implies.length === 0) continue;
      for (const imp of rule.implies) {
        expect(typeof imp, `${rule.id} の implies がオブジェクト形式ではありません`).toBe('object');
        if (typeof imp === 'object') {
          const targetRule = ruleById.get(imp.id);
          expect(targetRule, `${rule.id} の推論先 ${imp.id} が存在しません`).toBeDefined();
          expect(typeof imp.runtimeStatus, `${rule.id} -> ${imp.id} に runtimeStatus が定義されていません`).toBe('string');
          expect(typeof imp.confidenceFactor, `${rule.id} -> ${imp.id} に confidenceFactor が定義されていません`).toBe('number');
          ruleEdges.push({
            sourceId: rule.id,
            sourceName: rule.name,
            targetId: imp.id,
            targetName: targetRule ? targetRule.name : imp.id,
            relation: imp.relation,
            runtimeStatus: imp.runtimeStatus ?? '',
            confidenceFactor: imp.confidenceFactor ?? NaN,
          });
        }
      }
    }

    // 2. 仕様書 §4 セクションを切り出す
    const sec4Start = specContent.indexOf('## 4. Implication Engine（連動推論）連動マトリクス');
    const sec5Start = specContent.indexOf('## 5.');
    expect(sec4Start).toBeGreaterThan(-1);
    expect(sec5Start).toBeGreaterThan(sec4Start);
    const sec4Content = specContent.slice(sec4Start, sec5Start);

    // 3. §4 の Mermaid 図からエッジを抽出
    const mermaidMatch = sec4Content.match(/```mermaid([\s\S]*?)```/);
    expect(mermaidMatch, '仕様書 §4 に Mermaid 図が見つかりません').not.toBeNull();
    const mermaidBody = mermaidMatch ? mermaidMatch[1] : '';
    const nodeLabelMap = new Map<string, string>();
    const diagramEdges: ImpliesEdge[] = [];

    for (const rawLine of mermaidBody.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith('graph ')) continue;
      const edgeMatch = line.match(
        /^([A-Za-z0-9_]+)(?:\["([^"]+)"\])?\s*-->\|"([^"|]+)"\|\s*([A-Za-z0-9_]+)(?:\["([^"]+)"\])?$/
      );
      if (!edgeMatch) continue;
      const [, srcVar, srcLabel, edgeLabel, dstVar, dstLabel] = edgeMatch;
      if (srcLabel) nodeLabelMap.set(srcVar, srcLabel);
      if (dstLabel) nodeLabelMap.set(dstVar, dstLabel);

      const sourceName = nodeLabelMap.get(srcVar) || srcVar;
      const targetName = nodeLabelMap.get(dstVar) || dstVar;
      const srcRule = ruleByName.get(sourceName);
      const dstRule = ruleByName.get(targetName);
      expect(srcRule, `Mermaid図の推論元「${sourceName}」がルールに存在しません`).toBeDefined();
      expect(dstRule, `Mermaid図の推論先「${targetName}」がルールに存在しません`).toBeDefined();

      const labelParts = edgeLabel.match(/^([a-z-]+)\s*\(([a-z-]+)(?:,\s*([0-9.]+))?\)$/);
      expect(labelParts, `Mermaid図のエッジラベル形式が不正です: ${edgeLabel}`).not.toBeNull();
      if (srcRule && dstRule && labelParts) {
        diagramEdges.push({
          sourceId: srcRule.id,
          sourceName: srcRule.name,
          targetId: dstRule.id,
          targetName: dstRule.name,
          relation: labelParts[1],
          runtimeStatus: labelParts[2],
          confidenceFactor: labelParts[3] !== undefined ? Number(labelParts[3]) : NaN,
        });
      }
    }

    // 4. §4 の連動推論マトリクス表からエッジを抽出
    const tableEdges: ImpliesEdge[] = [];
    for (const rawLine of sec4Content.split('\n')) {
      const trimmed = rawLine.trim();
      if (!trimmed.startsWith('| **')) continue;
      const cols = trimmed.split('|').map((c) => c.trim());
      if (cols.length < 6) continue;
      const srcCellMatch = cols[1].match(/^\*\*(.+?)\*\*\s*\(`([^`]+)`\)$/);
      const dstCellMatch = cols[2].match(/^\*\*(.+?)\*\*\s*\(`([^`]+)`\)$/);
      expect(srcCellMatch, `表の推論元セル形式が不正です: ${cols[1]}`).not.toBeNull();
      expect(dstCellMatch, `表の推論先セル形式が不正です: ${cols[2]}`).not.toBeNull();
      if (!srcCellMatch || !dstCellMatch) continue;
      const sourceName = srcCellMatch[1];
      const sourceId = srcCellMatch[2];
      const targetName = dstCellMatch[1];
      const targetId = dstCellMatch[2];
      const relation = cols[3].replace(/`/g, '');
      const runtimeStatus = cols[4].replace(/`/g, '');
      const confidenceFactor = Number(cols[5].replace(/`/g, ''));
      tableEdges.push({
        sourceId,
        sourceName,
        targetId,
        targetName,
        relation,
        runtimeStatus,
        confidenceFactor,
      });
    }

    const sortKey = (e: ImpliesEdge) => `${e.sourceId}->${e.targetId}`;
    const sortedRules = [...ruleEdges].sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
    const sortedDiagram = [...diagramEdges].sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
    const sortedTable = [...tableEdges].sort((a, b) => sortKey(a).localeCompare(sortKey(b)));

    expect(sortedTable).toEqual(sortedRules);
    expect(sortedDiagram).toEqual(sortedRules);
  });

  it('README.md のカバレッジ表がルール定義（generate-spec-catalog.mjs の生成結果）と完全に一致していること (T13 / DOC-07)', () => {
    const rootDir = path.resolve(__dirname, '..');
    const readmeContent = fs.readFileSync(path.join(rootDir, 'README.md'), 'utf-8');
    const catalogJson = JSON.parse(
      fs.readFileSync(path.join(rootDir, 'data', 'advisories', 'catalog.json'), 'utf-8')
    ) as {
      products?: Record<string, { eol?: unknown; osv?: unknown; nvd?: unknown }>;
    };

    const startMarker = '## 対応技術スタック & 診断カバレッジ (Coverage)';
    const endMarker = '\n## システムアーキテクチャ';
    const startIdx = readmeContent.indexOf(startMarker);
    const endIdx = readmeContent.indexOf(endMarker);
    expect(startIdx).toBeGreaterThan(-1);
    expect(endIdx).toBeGreaterThan(startIdx);

    const coverageSection = readmeContent.slice(startIdx, endIdx);

    // 実行時バージョン取得 (MAIN world) 対応の技術ID一覧 (scripts/generate-spec-catalog.mjs と同一)
    const runtimeVersionTechIds = new Set([
      'jquery',
      'bootstrap',
      'vue',
      'lodash',
      'moment',
      'angularjs',
    ]);

    const escapePipeForReadme = (str: string): string => {
      if (!str) return '-';
      return str.replace(/\|/g, '\\|').replace(/\]\(/g, '\\]\\(');
    };

    const summarizeRuleSignalsForReadme = (rule: TechnologyRule): string => {
      const seen = new Set<string>();
      const parts: string[] = [];
      for (const s of rule.signals || []) {
        const label = s.target ? `${s.type} (${s.target})` : s.type;
        if (!seen.has(label)) {
          seen.add(label);
          parts.push(escapePipeForReadme(label));
        }
      }
      if (runtimeVersionTechIds.has(rule.id)) {
        parts.push('実行時バージョン取得 (MAIN world)');
      }
      return parts.join(', ');
    };

    // README の表から各技術行を抽出して検証
    const tableRowMap = new Map<
      string,
      {
        groupCol: string;
        name: string;
        verCol: string;
        eolCol: string;
        cveCol: string;
        methods: string;
      }
    >();

    for (const rawLine of coverageSection.split('\n')) {
      const trimmed = rawLine.trim();
      if (!trimmed.startsWith('|')) continue;
      if (trimmed.startsWith('| 分類') || trimmed.startsWith('|---')) continue;

      const cols = trimmed.split(/(?<!\\)\|/).map((c) => c.trim());
      if (cols.length < 7) continue;

      const nameCell = cols[2];
      const nameMatch = nameCell.match(/^(?:\*\*(.+?)\*\*|(.+?))\s*\(`([^`]+)`\)$/);
      if (!nameMatch) continue;

      const techName = (nameMatch[1] || nameMatch[2]).trim();
      const techId = nameMatch[3].trim();

      tableRowMap.set(techId, {
        groupCol: cols[1],
        name: techName,
        verCol: cols[3],
        eolCol: cols[4],
        cveCol: cols[5],
        methods: cols[6],
      });
    }

    // 全ルール数と表の行数が一致すること
    expect(tableRowMap.size).toBe(allRules.length);

    for (const rule of allRules) {
      const row = tableRowMap.get(rule.id);
      expect(
        row,
        `README.md のカバレッジ表に ${rule.name} (${rule.id}) が存在しません`
      ).toBeDefined();
      if (!row) continue;

      expect(row.name).toBe(rule.name);

      // バージョン特定列: versionRegex または実行時バージョン取得がある技術のみ ✅
      const hasVer =
        rule.signals.some((s) => Boolean(s.versionRegex)) || runtimeVersionTechIds.has(rule.id);
      expect(
        row.verCol,
        `${rule.name} (${rule.id}) の「バージョン特定」列が不正です`
      ).toBe(hasVer ? '✅' : '-');

      // EOL判定・既知脆弱性 (CVE) 列の一致確認
      const prod = catalogJson.products?.[rule.id];
      const expectedEol = prod?.eol ? '✅' : '-';
      const expectedCve = prod?.osv || prod?.nvd ? '✅' : '-';
      expect(
        row.eolCol,
        `${rule.name} (${rule.id}) の「EOL判定」列が catalog.json と一致しません`
      ).toBe(expectedEol);
      expect(
        row.cveCol,
        `${rule.name} (${rule.id}) の「既知脆弱性 (CVE)」列が catalog.json と一致しません`
      ).toBe(expectedCve);

      // 主な検出手法列の一致確認
      const expectedMethods = summarizeRuleSignalsForReadme(rule);
      expect(
        row.methods,
        `${rule.name} (${rule.id}) の「主な検出手法」列がルール定義と一致しません`
      ).toBe(expectedMethods);
    }
  });

  it('README.md に古い記載（「全125テスト」「v1.6.0」「siteChecker/」）が残っていないこと (T13 / DOC-07)', () => {
    const rootDir = path.resolve(__dirname, '..');
    const readmeContent = fs.readFileSync(path.join(rootDir, 'README.md'), 'utf-8');

    expect(readmeContent).not.toContain('全125テスト');
    expect(readmeContent).not.toContain('v1.6.0');
    expect(readmeContent).not.toContain('siteChecker/');
  });

  it('v1.7.1 T12: 版の表記が 1.7.1 に統一され、旧フォールバック文字列が無く、DB の minExtensionVersion は 1.7.0 のままであること', () => {
    const rootDir = path.resolve(__dirname, '..');
    const targetVersion = '1.7.1';

    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf-8'));
    const lock = JSON.parse(fs.readFileSync(path.join(rootDir, 'package-lock.json'), 'utf-8'));
    const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, 'public', 'manifest.json'), 'utf-8'));
    const advisoryDb = JSON.parse(
      fs.readFileSync(path.join(rootDir, 'src', 'detection', 'advisory-db.json'), 'utf-8')
    );

    expect(pkg.version).toBe(targetVersion);
    expect(lock.version).toBe(targetVersion);
    expect(lock.packages?.['']?.version).toBe(targetVersion);
    // DB だけの自動リリースは manifest に 4 つ目の番号を付ける（例: 1.7.1.1）。package.json と RULES_VERSION は 3 つのまま
    expect(manifest.version).toMatch(new RegExp(`^${targetVersion.replace(/\./g, '\\.')}(\\.\\d+)?$`));
    expect(RULES_VERSION).toBe(targetVersion);
    expect(advisoryDb.minExtensionVersion).toBe('1.7.0');

    const fallbackFiles = [
      'src/background/service-worker.ts',
      'src/popup/popup.ts',
      'src/dashboard/dashboard.ts',
      'src/export/markdown.ts',
      'src/export/csv.ts',
    ];
    for (const rel of fallbackFiles) {
      const text = fs.readFileSync(path.join(rootDir, rel), 'utf-8');
      const stale = text.match(/'1\.(?:6\.\d+|7\.0)(?:\.\d+)?'/g) || [];
      expect(stale, `${rel} に旧バージョン文字列が残っています`).toEqual([]);
      expect(text).toContain(`'${targetVersion}'`);
    }

    expect(specContent).toContain(`**対象バージョン：** v${targetVersion}`);
  });

  it('v1.7.1 T12: 仕様書と保守ガイドが T01〜T11 の結果および一括取得・チェッカーの運用ルールと整合していること', () => {
    const rootDir = path.resolve(__dirname, '..');
    const guideContent = fs.readFileSync(path.join(rootDir, 'docs', 'MAINTENANCE_GUIDE.md'), 'utf-8');

    // 仕様書: 件数の定義・通信先の定義・Cookie 6 用途・CSP 最大 MEDIUM
    expect(specContent).toContain('requiresAttentionCount');
    expect(specContent).toContain("performance.getEntriesByType('resource')");
    expect(specContent).toContain('referenceOnlyUrls');
    expect(specContent).toContain('advertising');
    expect(specContent).toContain('consent');
    expect(specContent).toContain('SEC-COOKIE-SECURE-GENERAL');
    expect(specContent).toContain('最大 `MEDIUM`');

    // 保守ガイド: 一括取得スクリプト・チェッカーの使い方と公開リポジトリ掲載禁止の明記
    expect(guideContent).toContain('scripts/report-lint.mjs');
    expect(guideContent).toContain('npm run reports:lint');
    expect(guideContent).toContain('scripts/collect-reports.mjs');
    expect(guideContent).toContain('npm run reports:collect');
    expect(guideContent).toContain('実サイトの診断レポートを公開リポジトリに載せないでください');
  });
});

