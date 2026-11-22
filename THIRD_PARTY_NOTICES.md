# サードパーティデータの出典とライセンス (Third-Party Notices)

本拡張機能（Web Technology & Security Inspector）のソースコードは [MIT License](LICENSE) のもとで提供されています。
本拡張機能に同梱されているデータおよびルールセットは、それぞれの提供元のライセンス・利用規約に従います。

---

## 同梱データの出典とライセンス一覧

### NIST National Vulnerability Database (NVD)

- 出典URL: https://nvd.nist.gov/
- ライセンス: 公有（米国政府の著作物）。NVD API の利用規約に従います
- 利用規約URL: https://nvd.nist.gov/developers/terms-of-use
- 同梱内容: CVE の CVSS スコア・ベクトル・参照 URL
- 加工の有無: 必要な項目だけを抜き出して加工しています。加工した内容は NVD が提供したものではなく、NVD による承認・認定も受けていません。
- 利用規定に基づく表示文:
  > This product uses the NVD API but is not endorsed or certified by the NVD.

### GitHub Advisory Database (OSV.dev 経由: npm / Packagist)

- 出典URL: https://github.com/github/advisory-database
- ライセンス: CC BY 4.0
- ライセンスURL: https://creativecommons.org/licenses/by/4.0/
- 同梱内容: GHSA の ID・影響範囲・タイトル
- 加工の有無: OSV.dev 経由で取得し、影響範囲・重大度・タイトルを抜き出して加工しています。

### OSV.dev (Ubuntu Security Notices)

- 出典URL: https://github.com/canonical/ubuntu-security-notices
- ライセンス: CC BY-SA 4.0（Ubuntu の部分）
- ライセンスURL: https://creativecommons.org/licenses/by-sa/4.0/
- 同梱内容: CVE ごとの状態・修正版・USN の ID
- 加工の有無: OSV.dev 経由で取得し、状態・修正版を抜き出して加工しています。加工した Ubuntu の部分も CC BY-SA 4.0 です。

### OSV.dev (Debian Security Tracker)

- 出典URL: https://osv.dev/list?ecosystem=Debian
- ライセンス: ライセンスの明記なし（出典のみ表示）
- 同梱内容: CVE ごとの状態・修正版
- 加工の有無: OSV.dev 経由で取得し、状態・修正版を抜き出して加工しています。

### endoflife.date

- 出典URL: https://endoflife.date/
- ライセンス: MIT License
- ライセンスURL: https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE
- 同梱内容: 製品のサポート期間（サイクルごとのサポート終了日）
- 加工の有無: サポート期間だけを抜き出して加工しています（製品の説明文は使っていません）。
- 許諾表示・ライセンス全文:

```text
Copyright 2020 endoflife.date contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### CISA Known Exploited Vulnerabilities Catalog

- 出典URL: https://github.com/cisagov/kev-data
- ライセンス: CC0 1.0
- ライセンスURL: https://creativecommons.org/publicdomain/zero/1.0/
- 同梱内容: 悪用が確認された CVE の一覧
- 加工の有無: CVE の ID だけを使い、該当する脆弱性に印を付けています（加工）。

### Public Suffix List

- 出典URL: https://publicsuffix.org/
- ライセンス: MPL 2.0
- ライセンスURL: https://mozilla.org/MPL/2.0/
- 元のファイルURL: https://publicsuffix.org/list/public_suffix_list.dat
- 生成ファイル: src/security/psl-rules.generated.ts
- 同梱内容: ドメインの区切りの規則（src/security/psl-rules.generated.ts）
- 加工の有無: 規則を TypeScript の形に変換しています（生成ファイルの先頭に MPL 2.0 の表示を残しています、加工）。
- 本文への参照: Mozilla Public License 2.0 (MPL 2.0) の全文は https://mozilla.org/MPL/2.0/ を参照してください。
