# v1.8.1 作業記録

各工程の終わりに、次の形式で追記してください。完了報告書の材料になります。このファイルはコミットされるので、作業者のユーザー名・ローカルパス・ツールの製品名は書かないでください（担当は「設計とテストの担当」「実装の担当」と書く）。

```
## T00 設計  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <指示書に書かれていなかったことをどう決めたか>
- 外部の事実: <事実 — 一次資料の URL（確認日）。無ければ「なし」>
- 未解決: <あれば>

## T00 実装  (YYYY-MM-DD HH:MM)
- 変更ファイル: <path>, <path>
- 判断したこと: <…>
- 未解決: <あれば>
```

---

## T01 設計  (2026-11-14 03:32)
- 変更ファイル: docs/dev/v1.8.1/design/T01.md（新規）, tests/dpkg-version.test.ts（新規）
- 判断したこと:
  - 新しいモジュール `src/security/dpkg-version.ts` の公開 API を `parseDpkgVersion(s: string | null | undefined): { epoch, upstream, revision } | null` と `compareDpkgVersions(a, b): -1 | 0 | 1 | null` に決めた。revision が無いときは `''`、epoch が無いときは 0。
  - dpkg のテスト（t-version.c）は版を「組」で比べるので、同じ意味の文字列に書き直して取り込んだ。空の版どうしの比較は文字列にできないので取り込まず、upstream が `a`・`b` の比較は「数字以外で始まる upstream は null」と両立させるため先頭に `0` を付けた（設計メモ「仕様の解釈」1）。
  - upstream のコロンは、Policy の文字の一覧には無いが dpkg の実装とテストが受け付けるので、dpkg に合わせて許す（受け入れ条件「t-version.c の例がすべて成り立つ」のため）。
  - 前後のスペース・タブは dpkg と同じく無視し、途中の空白は null。epoch は数字だけ・上限 2147483647（dpkg の `strtol` が受ける `+1:` などは安全側で null）。
  - 数字の部分は数に変換せず 1 文字ずつ比べる（桁の多い数のテストを置いた）。
  - 「isLinuxPackageVersion と version-matcher の挙動は変えない」は、実装前に実測した戻り値を固定するテストで確かめる。
  - 実装の前は、モジュールが無いためファイル全体が失敗することを確認した。設計の担当が規則どおりの参照の実装（コミットしない）で全件が通ることも確かめた。次の版を前提にした test-hygiene の検査でも違反は無い。
- 外部の事実:
  - 版の形式・使える文字・比較の手順（`~` は空より前、英字は記号より前、revision 無しは 0）— https://www.debian.org/doc/debian-policy/ch-controlfields.html#version （Debian Policy 4.7.4.1、2026-11-14）
  - dpkg のテストの比較例・解析の例 — https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/t/t-version.c （2026-11-14。git.dpkg.org は自動取得を拒否したため Salsa で確認）
  - dpkg の比較と解析の実装（`order`・`verrevcmp`・`parseversion`）— https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/version.c 、https://salsa.debian.org/dpkg-team/dpkg/-/raw/main/lib/dpkg/parsehelp.c （2026-11-14）
- 未解決: なし
