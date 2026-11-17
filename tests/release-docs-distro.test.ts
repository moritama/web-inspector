/**
 * v1.8.1 T08: 版上げと文書の受け入れテスト（NEW-04 の文書）
 *
 * - PRIVACY_POLICY に、同梱データに OS ディストリの修正情報を加えたこと・外部へ送信しないこと・収集する情報が増えないことが
 *   英語と日本語の両方で書かれていること。manifest の権限がすべて PRIVACY_POLICY の権限の表に書かれていること
 * - MAINTENANCE_GUIDE に、対応表（distro-map.json）の更新手順（ずれの報告を受けたら人が一次資料で確かめて更新）が書かれていること
 * - README の機能一覧に NEW-04 の行があり、推定の結果を「安全」「該当なし」と断定していないこと（H4）
 *
 * 版の一致（C12 相当）は spec-integrity.test.ts・release-docs.test.ts・release-version.test.ts が package.json の版で確かめる。
 * DB だけのリリースの予行は ci-db-release-rehearsal.test.ts・advisory-distro-compat.test.ts が確かめる。
 * このファイルには版の文字列を書かない（test-hygiene が検査する）。文面の一字一句は確かめず、要点だけを確かめる（文面は人が承認する）。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';

const read = (rel: string): string => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');

/** Debian と Ubuntu の両方を書いた行（PRIVACY_POLICY の v1.8.1 の項は、言語ごとに 1 行の箇条書きにする） */
const distroLines = (text: string): string[] => text.split('\n').filter((line) => /Debian/.test(line) && /Ubuntu/.test(line));

/** 日本語の文字（ひらがな・カタカナ）を含む行かどうか */
const hasKana = (line: string): boolean => /[぀-ヿ]/.test(line);

/** manifest の permissions と host_permissions のうち、PRIVACY_POLICY の権限の表（第 4 章）に `名前` で書かれていないもの */
function undocumentedPermissions(manifest: { permissions?: string[]; host_permissions?: string[] }, privacyPolicy: string): string[] {
  const start = privacyPolicy.search(/^##\s*4\.\s*Permissions/m);
  const rest = start >= 0 ? privacyPolicy.slice(start) : '';
  const next = rest.slice(1).search(/^##\s/m);
  const section = next >= 0 ? rest.slice(0, next + 1) : rest;
  const tableRows = section.split('\n').filter((line) => line.trim().startsWith('|'));
  const all = [...(manifest.permissions ?? []), ...(manifest.host_permissions ?? [])];
  return all.filter((perm) => !tableRows.some((row) => row.includes(`\`${perm}\``)));
}

describe('T08: PRIVACY_POLICY（OS ディストリの修正情報の同梱）', () => {
  const pp = read('PRIVACY_POLICY.md');
  const lines = distroLines(pp);
  const english = lines.filter((line) => !hasKana(line));
  const japanese = lines.filter(hasKana);

  it('英語の項が、同梱のデータに Debian / Ubuntu の修正情報を加えたことを書いていること', () => {
    expect(english.length, 'Debian と Ubuntu を書いた英語の行がありません').toBeGreaterThan(0);
    expect(english.some((line) => /bundled|includes?|included/i.test(line) && /fix/i.test(line))).toBe(true);
  });

  it('英語の項が、そのデータのために外部へ送信しないこと（照合は端末内）を書いていること', () => {
    expect(
      english.some((line) => /\b(?:not|never|no)\b[^.]*\b(?:send|sent|transmit|transmitted)\b/i.test(line)),
      'Debian / Ubuntu の英語の行に、送信しない旨がありません'
    ).toBe(true);
  });

  it('英語の項が、収集する情報が増えないことを書いていること', () => {
    expect(
      english.some((line) => /collect/i.test(line) && /(?:\bnot\b[^.]*\bincrease|\bno\s+(?:new|additional)\b)/i.test(line)),
      'Debian / Ubuntu の英語の行に、収集する情報が増えない旨がありません'
    ).toBe(true);
  });

  it('日本語の項が、同梱のデータに OS ディストリの修正情報を加えたことを書いていること', () => {
    expect(japanese.length, 'Debian と Ubuntu を書いた日本語の行がありません').toBeGreaterThan(0);
    expect(japanese.some((line) => /ディストリ/.test(line) && /修正/.test(line) && /同梱/.test(line))).toBe(true);
  });

  it('日本語の項が、外部へ送信しないことを書いていること', () => {
    expect(
      japanese.some((line) => /送信[^。]*(?:しません|ありません|行いません)/.test(line)),
      'Debian / Ubuntu の日本語の行に、送信しない旨がありません'
    ).toBe(true);
  });

  it('日本語の項が、収集する情報が増えないことを書いていること', () => {
    expect(
      japanese.some((line) => /(?:収集|取得)する情報[^。]*増え(?:ません|ていません)/.test(line)),
      'Debian / Ubuntu の日本語の行に、収集する情報が増えない旨がありません'
    ).toBe(true);
  });

  it('外部送信ゼロの原則（第 1 章）の記述が残っていること（陰性: 項を足しても原則を書き換えない）', () => {
    expect(pp).toMatch(/^##\s*1\.\s*No Data Transmission/m);
    expect(pp).toMatch(/no external network connections/i);
    expect(pp).toContain('外部の解析サーバー等への通信も一切行いません');
  });
});

describe('T08: manifest の権限と PRIVACY_POLICY の権限の表（収集する情報が増えないこと）', () => {
  const manifest = JSON.parse(read('public/manifest.json')) as { permissions?: string[]; host_permissions?: string[] };
  const pp = read('PRIVACY_POLICY.md');

  it('manifest の permissions と host_permissions は、すべて PRIVACY_POLICY の権限の表に書かれていること', () => {
    expect((manifest.permissions ?? []).length).toBeGreaterThan(0);
    expect(undocumentedPermissions(manifest, pp)).toEqual([]);
  });

  it('表に無い権限を manifest に足すと、検査が拾うこと（陰性: 検査自身の確認）', () => {
    const extended = { ...manifest, permissions: [...(manifest.permissions ?? []), 'synthetic-permission'] };
    expect(undocumentedPermissions(extended, pp)).toEqual(['synthetic-permission']);
    // 表の外（本文）にだけ書かれた名前は、表に書かれたとみなさない
    expect(undocumentedPermissions(extended, `${pp}\n\n\`synthetic-permission\`\n`)).toEqual(['synthetic-permission']);
  });
});

/**
 * 見出し（# 〜 ###）で区切った節のうち、needle を含む節をつないで返す。
 * 対応表の更新手順の要点が、対応表のファイル名を書いた節の中にあることを確かめるために使う（#### 以下の小見出しは節を区切らない）
 */
function sectionsContaining(text: string, needle: string): string {
  const sections: string[] = [];
  let current: string[] = [];
  for (const line of text.split('\n')) {
    if (/^#{1,3}\s/.test(line) && current.length > 0) {
      sections.push(current.join('\n'));
      current = [];
    }
    current.push(line);
  }
  if (current.length > 0) sections.push(current.join('\n'));
  return sections.filter((s) => s.includes(needle)).join('\n');
}

describe('T08: MAINTENANCE_GUIDE（対応表の更新手順）', () => {
  const guide = sectionsContaining(read('docs/MAINTENANCE_GUIDE.md'), 'data/advisories/distro-map.json');

  it('節を切り出す関数は、needle を含む節だけを返すこと（検査自身の確認）', () => {
    const text = ['# A', 'x', '## B', 'needle', '#### B1', 'y', '## C', 'z'].join('\n');
    expect(sectionsContaining(text, 'needle')).toBe(['## B', 'needle', '#### B1', 'y'].join('\n'));
    expect(sectionsContaining(text, 'none')).toBe('');
  });

  it('対応表のファイルと週次の突き合わせのスクリプトが、同じ節に書かれていること', () => {
    expect(guide, 'MAINTENANCE_GUIDE に data/advisories/distro-map.json を書いた節がありません').not.toBe('');
    expect(guide).toContain('scripts/advisories/check-distro-map.mjs');
  });

  it('ずれの報告（週次のボット PR の「対応表のずれ」）を受けて更新することが書かれていること', () => {
    expect(guide).toContain('対応表のずれ');
  });

  it('人が一次資料で確かめて更新し、evidenceUrl と verifiedAt を記録することが書かれていること', () => {
    expect(guide).toContain('一次資料');
    expect(guide).toMatch(/人が/);
    expect(guide).toContain('evidenceUrl');
    expect(guide).toContain('verifiedAt');
  });

  it('突き合わせは対応表を自動では書き換えないことが書かれていること（H3）', () => {
    expect(guide).toMatch(/(?:自動では|自動で)書き換え(?:ません|ない)|書き換えません/);
  });
});

describe('T08: README（機能一覧の NEW-04）', () => {
  const readme = read('README.md');
  const rows = readme.split('\n').filter((line) => line.trim().startsWith('|') && line.includes('NEW-04'));

  it('機能一覧の表に NEW-04 の行があり、Debian と Ubuntu に触れていること', () => {
    expect(rows.length, 'README の表に NEW-04 の行がありません').toBeGreaterThan(0);
    expect(rows.some((row) => /Debian/.test(row) && /Ubuntu/.test(row))).toBe(true);
  });

  it('NEW-04 の行は、推定にもとづく結果を「安全」「該当なし」「Not Affected」と書いていないこと（H4・陰性）', () => {
    for (const row of rows) {
      expect(row).not.toMatch(/安全|該当なし|Not Affected/i);
    }
  });
});
