// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * DOMシグナル到達性テスト (tests/rule-reachability.test.ts)
 * 
 * ALL_TECHNOLOGY_RULES に定義されたすべての type: 'dom' シグナルが、
 * content-script (extractDomSignals) により正しく収集され、
 * DetectionEngine により到達・検出されることを自動検証します (T06 / DOC-01)
 */

import { describe, expect, it } from 'vitest';
import { extractDomSignals } from '../src/content/content-script';
import { DetectionEngine } from '../src/detection/engine';
import { ALL_TECHNOLOGY_RULES, RuleSignal, TechnologyRule } from '../src/detection/rules';
import { getDomSignalFixture } from './fixtures/dom-signal-fixtures';

describe('DOMシグナル到達性テスト (Rule Reachability: DOC-01)', () => {
  const engine = new DetectionEngine();

  // ルール定義からすべての type: 'dom' シグナルを抽出
  const allDomSignals: Array<{ rule: TechnologyRule; signal: RuleSignal; signalIndex: number }> = [];

  for (const rule of ALL_TECHNOLOGY_RULES) {
    rule.signals.forEach((sig, idx) => {
      if (sig.type === 'dom') {
        allDomSignals.push({ rule, signal: sig, signalIndex: idx });
      }
    });
  }

  it('ルール定義の全 type: "dom" シグナル (計26件) に対するフィクスチャが漏れなく定義されていること', () => {
    expect(allDomSignals.length).toBeGreaterThanOrEqual(26);
    const missing: string[] = [];

    for (const item of allDomSignals) {
      const fixture = getDomSignalFixture(item.rule.id, item.signal.target);
      if (!fixture) {
        missing.push(`${item.rule.id} (target: ${item.signal.target})`);
      }
    }

    expect(
      missing,
      `以下のDOMシグナルに対するフィクスチャが未定義です: ${missing.join(', ')}`
    ).toEqual([]);
  });

  // 単独では確信度50未満で結果から除外される弱いシグナル (Bootstrap .container: 40) の許可リスト
  const lowConfidenceAllowedRuleIds = new Set(['bootstrap']);

  it.each(allDomSignals)(
    'シグナル到達性検証: $rule.name (id: $rule.id, target: $signal.target)',
    ({ rule, signal }) => {
      const fixture = getDomSignalFixture(rule.id, signal.target);
      expect(fixture).toBeDefined();
      if (!fixture) return;

      // happy-dom での iframe 読み込み抑制エラー（console.error）の抑制
      const originalConsoleError = console.error;
      if (rule.id === 'google-tag-manager') {
        console.error = (...args: unknown[]) => {
          if (
            args[0] &&
            typeof args[0] === 'object' &&
            'message' in (args[0] as Record<string, unknown>) &&
            String((args[0] as Record<string, unknown>).message).includes('Iframe page loading is disabled')
          ) {
            return;
          }
          originalConsoleError(...args);
        };
      }

      try {
        document.head.innerHTML = '';
        document.body.innerHTML = '';
        document.title = '';

        if (fixture.title) {
          document.title = fixture.title;
        }
        if (fixture.headHtml) {
          document.head.innerHTML = fixture.headHtml;
        }
        if (fixture.html) {
          if (fixture.html.startsWith('<meta') || fixture.html.startsWith('<title')) {
            document.head.innerHTML += fixture.html;
          } else {
            document.body.innerHTML = fixture.html;
          }
        }

        const dom = extractDomSignals();
        const detected = engine.detect({ url: dom.url, dom });
        const detectedTechNames = detected.map((t) => t.technology);

        if (lowConfidenceAllowedRuleIds.has(rule.id)) {
          // 確信度50未満の弱いシグナルはエビデンス（domMarkers）として収集されていることを検証
          expect(dom.domMarkers.length).toBeGreaterThan(0);
          expect(dom.domMarkers).toContain('.container');
        } else {
          expect(
            detectedTechNames,
            `技術「${rule.name}」(${rule.id}) が検出されませんでした (検出結果: ${detectedTechNames.join(', ')})`
          ).toContain(rule.name);
        }
      } finally {
        console.error = originalConsoleError;
      }
    }
  );
});
