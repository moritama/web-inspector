/**
 * v1.8.2 T08: 版上げと文書の受け入れテスト（DETECTION_SPECIFICATION・MAINTENANCE_GUIDE・PRIVACY_POLICY・manifest）
 *
 * - DETECTION_SPECIFICATION に、この版の判定と表示の変更（A・B・C・D-1・D-2・D-3・E）の要点が書かれていること。
 *   古くなった記述（「HTTP 接続のページでは COOP・COEP を対象外」）が COOP・COEP の項に残っていないこと
 * - MAINTENANCE_GUIDE に、レポートの lint の R10、CI の補助スクリプト（content-script の IIFE・出典のチェック）、
 *   同梱データの出典を変えるときに一緒に直すファイルが書かれていること
 * - PRIVACY_POLICY は、通信も収集する情報も増えないので変更を要しない（設計メモ「仕様の解釈」）。
 *   原則の記述が残っていること、manifest の権限が増えていないこと（既存の release-docs-distro.test.ts）、
 *   manifest の incognito が spanning のまま（H13）であることを確かめる
 *
 * 版の一致（package.json・lock・manifest・RULES_VERSION・予備の文字列・バッジ・仕様書の対象バージョン）は、
 * 既存の spec-integrity.test.ts・release-docs.test.ts・release-version.test.ts が package.json の版で確かめる。
 * このファイルには版の文字列を書かない（test-hygiene が検査する）。文面の一字一句は確かめず、要点（語）だけを確かめる。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';

const read = (rel: string): string => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');

/** 文書を行に分ける（Markdown の段落・箇条書き・表の行は 1 行に書く前提） */
const linesOf = (text: string): string[] => text.split('\n');

/** すべての語を含む行 */
const linesWithAll = (text: string, words: string[]): string[] =>
  linesOf(text).filter((line) => words.every((w) => line.includes(w)));

/**
 * 見出し（`#`〜`###`）で区切った節のうち、needle を含む節の本文（`####` 以下は同じ節）。
 * 見つからなければ空の配列
 */
function sectionsContaining(text: string, needle: string): string[] {
  const parts = text.split(/\n(?=#{1,3}\s)/);
  return parts.filter((p) => p.includes(needle));
}

describe('T08: 検査の補助関数の確認', () => {
  it('linesWithAll は、すべての語を含む行だけを返すこと', () => {
    const t = 'a b c\na b\nb c';
    expect(linesWithAll(t, ['a', 'b'])).toEqual(['a b c', 'a b']);
    expect(linesWithAll(t, ['z'])).toEqual([]);
  });

  it('sectionsContaining は、needle を含む ### までの節だけを返し、#### は同じ節に含めること', () => {
    const t = '## 1\nx\n### 1.1\nneedle\n#### sub\ny\n### 1.2\nz';
    const s = sectionsContaining(t, 'needle');
    expect(s.length).toBe(1);
    expect(s[0]).toContain('#### sub');
    expect(s[0]).not.toContain('### 1.2');
  });
});

describe('T08: DETECTION_SPECIFICATION（この版の判定と表示の変更）', () => {
  const spec = read('docs/DETECTION_SPECIFICATION.md');

  it('A: 親ドメインの Cookie（host-only でない）の名前だけを根拠にした検出は、確信度を 35（low）に下げることが書かれていること（H1・H2）', () => {
    const lines = linesWithAll(spec, ['hostOnly']);
    expect(lines.length, 'hostOnly を書いた行がありません').toBeGreaterThan(0);
    expect(lines.some((l) => l.includes('35') && /low|低/.test(l))).toBe(true);
  });

  it('A: スコープの判定に Set-Cookie の Domain 属性と document.cookie（スコープ不明）を使うことが書かれていること（§4.1 の表・H3）', () => {
    const scope = sectionsContaining(spec, 'hostOnly').join('\n');
    expect(scope).toContain('Domain');
    expect(scope).toContain('document.cookie');
  });

  it('D-1: SEC-COOP-01 と SEC-COEP-01 の項に、安全なコンテキスト（localhost を含む）で判定を切り替えることが書かれていること（H7）', () => {
    for (const id of ['SEC-COOP-01', 'SEC-COEP-01']) {
      const lines = linesWithAll(spec, [`\`${id}\``]);
      expect(lines.length, `${id} の項がありません`).toBeGreaterThan(0);
      expect(
        lines.some((l) => l.includes('localhost') && /安全なコンテキスト|secure context|isSecureContextUrl/i.test(l)),
        id
      ).toBe(true);
    }
  });

  it('D-1（陰性）: SEC-COOP-01 と SEC-COEP-01 の項に「HTTP 接続のページで（は）」対象外とする古い記述が残っていないこと', () => {
    for (const id of ['SEC-COOP-01', 'SEC-COEP-01']) {
      for (const line of linesWithAll(spec, [`\`${id}\``])) {
        expect(line, id).not.toContain('HTTP 接続のページで');
      }
    }
  });

  it('D-1: 安全なコンテキストの範囲（isSecureContextUrl。127.0.0.0/8・[::1] を含む）が書かれていること（H7）', () => {
    const lines = linesWithAll(spec, ['isSecureContextUrl']);
    expect(lines.length, 'isSecureContextUrl を書いた行がありません').toBeGreaterThan(0);
    const section = sectionsContaining(spec, 'isSecureContextUrl').join('\n');
    expect(section).toContain('127.0.0.0/8');
    expect(section).toContain('[::1]');
  });

  it('D-2: 通信先の総数 = First-Party + Third-Party + Local（localCount）が書かれていること（H8）', () => {
    const lines = linesWithAll(spec, ['localCount']);
    expect(lines.length, 'localCount を書いた行がありません').toBeGreaterThan(0);
    expect(lines.some((l) => l.includes('First-Party') && l.includes('Third-Party'))).toBe(true);
  });

  it('D-3: Cookie を調べるタブの保存先（getAllCookieStores の storeId）から読むことが書かれていること（H13）', () => {
    expect(linesWithAll(spec, ['getAllCookieStores', 'storeId']).length).toBeGreaterThan(0);
  });

  it('D-3: ヘッダー未観測のときの理由に、ページの再読み込みの案内を添えることが書かれていること', () => {
    expect(linesWithAll(spec, ['未観測', '再読み込み']).length).toBeGreaterThan(0);
  });

  it('B: content-script を IIFE で出力し、二重注入でも重複宣言にならないことが書かれていること（H6）', () => {
    expect(linesWithAll(spec, ['content-script', 'IIFE']).length).toBeGreaterThan(0);
  });

  it('C: 確信度付きのリリース名は formatDistroReleaseWithConfidence で 1 回だけ付けることが書かれていること（H4）', () => {
    expect(spec).toContain('formatDistroReleaseWithConfidence');
  });

  it('E: 同梱データの出典とライセンスが THIRD_PARTY_NOTICES.md にあることが書かれていること（H9）', () => {
    expect(spec).toContain('THIRD_PARTY_NOTICES.md');
  });

  it('陰性（H2・K3）: 親ドメインの Cookie の項で、検出した技術を「利用している」「安全」と断定していないこと', () => {
    for (const line of linesWithAll(spec, ['hostOnly'])) {
      expect(line).not.toMatch(/利用しています|安全です|該当なし/);
    }
  });
});

describe('T08: MAINTENANCE_GUIDE（この版で足した検査と出典の更新）', () => {
  const guide = read('docs/MAINTENANCE_GUIDE.md');

  it('レポートの lint の検査項目の表に R10（総数 = First-Party + Third-Party + Local）があること', () => {
    const rows = linesOf(guide).filter((l) => l.trim().startsWith('|') && l.includes('R10'));
    expect(rows.length).toBe(1);
    expect(rows[0]).toContain('Local');
  });

  it('陰性: 既存の R01〜R09 の行は残っていること（R10 を足すときに消さない）', () => {
    for (const id of ['R01', 'R05', 'R09']) {
      expect(linesOf(guide).some((l) => l.trim().startsWith('|') && l.includes(`**${id}**`)), id).toBe(true);
    }
  });

  it('CI の補助スクリプト scripts/ci/check-content-script-iife.mjs の目的（content-script が IIFE であること）が書かれていること', () => {
    const sections = sectionsContaining(guide, 'scripts/ci/check-content-script-iife.mjs');
    expect(sections.length).toBeGreaterThan(0);
    expect(sections.join('\n')).toContain('IIFE');
  });

  it('CI の補助スクリプト scripts/ci/check-data-sources.mjs の目的（license か licenseNote、THIRD_PARTY_NOTICES.md との一致）が書かれていること', () => {
    const section = sectionsContaining(guide, 'scripts/ci/check-data-sources.mjs').join('\n');
    expect(section.length).toBeGreaterThan(0);
    expect(section).toContain('licenseNote');
    expect(section).toContain('THIRD_PARTY_NOTICES.md');
  });

  it('同梱データの出典を足す・変えるときに一緒に直すファイル（sources.mjs・data-sources.ts・THIRD_PARTY_NOTICES.md）が同じ節に書かれていること', () => {
    const sections = sectionsContaining(guide, 'THIRD_PARTY_NOTICES.md').filter(
      (s) => s.includes('scripts/advisories/lib/sources.mjs') && s.includes('src/shared/data-sources.ts')
    );
    expect(sections.length).toBeGreaterThan(0);
  });

  it('同梱データの出典を変えた後は build-db で DB を作り直す（手で編集しない）ことが、同じ節に書かれていること', () => {
    const sections = sectionsContaining(guide, 'scripts/advisories/lib/sources.mjs');
    expect(sections.length).toBeGreaterThan(0);
    expect(sections.some((s) => s.includes('advisories:build'))).toBe(true);
  });
});

describe('T08: PRIVACY_POLICY と manifest（通信も収集する情報も増えないこと）', () => {
  const pp = read('PRIVACY_POLICY.md');
  const manifest = JSON.parse(read('public/manifest.json')) as { incognito?: unknown; permissions?: string[] };

  it('外部送信ゼロの原則（第 1 章）が残っていること', () => {
    expect(pp).toMatch(/^##\s*1\.\s*No Data Transmission/m);
    expect(pp).toContain('外部の解析サーバー等への通信も一切行いません');
  });

  it('H13: manifest の incognito は spanning のまま（キーが無い＝既定の spanning、または "spanning"）であること', () => {
    expect(manifest.incognito === undefined || manifest.incognito === 'spanning').toBe(true);
  });

  it('陰性（H13）: manifest を split や not_allowed に変えていないこと', () => {
    expect(manifest.incognito).not.toBe('split');
    expect(manifest.incognito).not.toBe('not_allowed');
  });

  it('陰性: Cookie の保存先を引くための新しい権限を足していないこと（chrome.cookies の getAllCookieStores は cookies 権限で使える）', () => {
    expect(manifest.permissions).toContain('cookies');
    expect(manifest.permissions ?? []).not.toContain('incognito');
  });
});
