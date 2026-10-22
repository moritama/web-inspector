/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合単体テスト (tests/advisory.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { matchOfflineAdvisories } from '../src/detection/advisory';

describe('オフライン既知脆弱性・EOL照合テスト (IMP-03)', () => {
  it('古いjQuery 2.2.4 に対して脆弱性とEOLが正確に検出されること', () => {
    const result = matchOfflineAdvisories('jQuery', '2.2.4');

    expect(result.technology).toBe('jQuery');
    expect(result.matchStatus).toBe('Potentially Affected');
    expect(result.advisories.length).toBeGreaterThan(0);

    // CVE-2015-9251 や CVE-2020-11022 などが含まれるか
    const cveIds = result.advisories.map((a) => a.id);
    expect(cveIds).toContain('CVE-2015-9251');

    // EOL状況
    expect(result.eolInfo.status).toBe('EOL');
  });

  it('サポート終了済みのPHP 7.4.33 に対してEOLおよび脆弱性が照合されること', () => {
    const result = matchOfflineAdvisories('PHP', '7.4.33');

    expect(result.eolInfo.status).toBe('EOL');
    expect(result.matchStatus).toBe('Potentially Affected');
  });

  it('安全な最新Bootstrap 5.3.3 に対しては脆弱性なし・Supportedと判定されること', () => {
    const result = matchOfflineAdvisories('Bootstrap', '5.3.3');

    expect(result.matchStatus).toBe('Not Affected');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Supported');
  });

  it('バージョンが不明な場合、断定を避けNeeds Reviewとなること', () => {
    const result = matchOfflineAdvisories('jQuery', null);

    expect(result.matchStatus).toBe('Needs Review');
    expect(result.advisories.length).toBe(0);
    expect(result.eolInfo.status).toBe('Unknown');
  });

  it('未登録の技術の場合はNo Dataとなること', () => {
    const result = matchOfflineAdvisories('UnknownCustomLib', '1.0.0');

    expect(result.matchStatus).toBe('No Data');
    expect(result.advisories.length).toBe(0);
  });
});
