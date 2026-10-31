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
import { ALL_TECHNOLOGY_RULES, TechnologyRule } from '../src/detection/rules';

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

  it('ルール定義と仕様書カタログの登録技術数が完全に一致すること (全68技術)', () => {
    expect(allRules.length).toBe(68);
    expect(specTechIds.length).toBe(68);
    expect(new Set(specTechIds).size).toBe(68);
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

    // 2. HTMLファイルのバージョンバッジ表示一致
    const htmlFiles = [
      path.join(rootDir, 'popup.html'),
      path.join(rootDir, 'dashboard.html'),
      path.join(rootDir, 'src', 'popup', 'popup.html'),
      path.join(rootDir, 'src', 'dashboard', 'dashboard.html'),
    ];

    for (const htmlPath of htmlFiles) {
      if (fs.existsSync(htmlPath)) {
        const content = fs.readFileSync(htmlPath, 'utf-8');
        expect(
          content.includes(`v${version}`),
          `${htmlPath} にバージョン "v${version}" が含まれていません`
        ).toBe(true);
      }
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
});

