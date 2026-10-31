# v1.6.6 開発キット — 作業者向け手順書（Antigravity CLI 版）

Antigravity CLI（コマンド名 `agy`）と夜間スクリプトに、v1.6.6 のコーディング・自動テスト・完了報告書の作成までを任せるための手順です。agy がコードを書き、テストの実行とコミットはスクリプトが行います。エージェントへの指示は、リポジトリ直下の `AGENTS.md` と [INSTRUCTIONS.md](./INSTRUCTIONS.md) に書いてあります。

おすすめは **夜間（無人）モード** です。夜に開始コマンドを1つ実行すれば、朝には完了報告書ができています。push は、朝に報告書と差分を確認してから人が行います。

## 全体の流れ

| いつ | 誰が | 何をする | 所要時間の目安 |
| --- | --- | --- | --- |
| 初回のみ | 人 | §1 初回だけの準備 | 15分 |
| 夜 | 人 | §2 開始前の手順（パッチ適用〜事前チェック） | 15分 |
| 夜 | 人 | §3 夜間モードで開始（コマンド1つ） | 1分 |
| 夜〜朝 | agy とスクリプト | T01〜T12 の実装（agy）、テスト・コミット（スクリプト）、完了報告書の作成 | 数時間 |
| 朝 | 人 | §5 朝の確認（報告書・E2E・目視）→ push と PR | 30〜60分 |

## 安全の仕組み（先に読んでください）

- agy は **無人モード（`agy -p`）＋サンドボックス（`--sandbox`）** で動かします。
  - サンドボックスにより、コマンドの書き込み先はリポジトリ（と一時フォルダ）に限られ、外部への通信もできません。`.git` にも書き込めないため、agy はコミットできません。
  - そのため agy には1回に1タスクだけ**ファイルの編集**をさせ、**テストの実行とコミットはスクリプトがサンドボックスの外で行います**。テストが落ちたら、失敗の内容を渡して agy に直させます（最大3回）。3回で直らなければ、変更をリポジトリの外に保存して元に戻し、「未完了」と記録して次のタスクへ進みます。
  - 変更禁止のファイル（DB・CI・指示書など）に変更があれば、コミットの前にスクリプトが元に戻します。
  - コマンドは原則すべて許可し、危険なものだけを拒否します。拒否するのは `git push`・タグ・ブランチ操作・`gh`・`curl`・依存パッケージの追加・脆弱性DBの取得・ストア提出・Web アクセスと、変更禁止ファイル（DB・CI・指示書など）への書き込みです。ルールは [agy-permissions.json](./agy-permissions.json) にあります。
  - Node.js のインストール先は読み取りだけ許可します（agy が型の確認などに node を使えるようにするため）。
  - 「原則すべて許可」にしているのは、agy の無人モードが、許可リストにないコマンドに当たると実行全体をその場で終了してしまうためです。
- **権限ルールは、夜間スクリプトの実行中だけ有効になります。** 開始時にユーザー設定（`~/.gemini/antigravity-cli/settings.json`）へ追加し、終了時（Ctrl+C で止めた場合も）に自動で削除します。ほかのフォルダで agy を使うときに影響しないようにするためです。
- **夜間実行中は push 先を無効にします。** `remote.origin.pushurl` を使えない値にし、終了時に元に戻します。万一、テストコードなどを経由して push が試みられても届きません。
- **「確認なしで全部進める」オプション（`--dangerously-skip-permissions`）は使いません。** 拒否ルールまで無効になるためです。
- 事前チェックでは、agy を短く1回起動して、上の仕組みが実際に効くことを確かめます。
  - できること: 許可したコマンドの実行、リポジトリ内のファイルの作成・編集
  - できないこと: `git tag`、リポジトリ外への書き込み、外部への通信
- 許可外の操作で実行が中断した場合は、「その操作を避けて続けるように」と添えてやり直します（試行回数に数えます）。
- E2E テストは夜間には実行しません（サンドボックス内で Chrome を起動できないため）。朝に人が実行します。
- ログはリポジトリの外の `~/web-inspector-overnight/<日時>/` に保存されます。

## 1. 初回だけの準備

1. Antigravity CLI をインストールする。
   ```bash
   curl -fsSL https://antigravity.google/cli/install.sh | bash
   agy --version          # 表示されればOK
   ```
   `agy: command not found` と出たら、`~/.zshrc` に `export PATH="$HOME/.local/bin:$PATH"` を追加し、ターミナルを開き直します。
2. ログインする: リポジトリ直下で `agy` を起動し、Google アカウントでログインします。フォルダの信頼やモデルの確認を求められたら、許可してから `/quit` で終了します。
3. Playwright の Chromium を入れる（朝の E2E 用）: リポジトリ直下で `npx playwright install chromium`。
4. Mac の設定: 電源アダプタにつないだまま、蓋を開けておく（蓋を閉じるとスリープする機種があります）。スリープ自体はスクリプトが `caffeinate` で防ぎます。
5. 利用枠について: 利用上限に達して途中で止まった場合は、スクリプトが15分おいて自動で再開します（全体で6回まで）。それでも終わらなければ、翌日に `--resume` で続きから再開できます。

## 2. 開始前の手順（毎回）

### (1) リポジトリ直下に移動し、状態を確認する

```bash
cd ~/（リポジトリの場所）/web-inspector
git switch main
git pull
git status                     # 「nothing to commit, working tree clean」ならOK
git config user.name; git config user.email   # 両方表示されればOK
```

- 変更が残っていたら、コミットするか `git stash` で退避します。
- `user.name` / `user.email` が空なら `git config --global user.name "名前"`、`git config --global user.email "メール"` で設定します（無いと `git am` が失敗します）。
- `.gitignore` に `node_modules` と `dist` が入っていることを確認します（無いと事前チェックで「クリーンでない」と判定されます）。

### (2) パッチ2つをリポジトリ直下に置く

使うパッチは `web-inspector-review-v1.6.5.patch` と `web-inspector-v1.6.6-agy-kit.patch` の2つです。Gemini CLI 用のキット（`...-gemini-kit.patch`）は使いません。

```bash
cp ~/Downloads/web-inspector-review-v1.6.5.patch ~/Downloads/web-inspector-v1.6.6-agy-kit.patch .
ls *.patch                     # 2つ表示されればOK
```

### (3) レビューパッチを main に入れる（入れ済みなら飛ばす）

```bash
ls scripts/advisories/build-db.mjs 2>/dev/null && echo "入れ済み（飛ばす）"
git am web-inspector-review-v1.6.5.patch
git log --oneline -2           # 先頭が「review v1.6.5: ...」ならOK
```

`warning: 1 line adds whitespace errors.` と表示されることがありますが、問題ありません（ファイル末尾の空行の警告です）。`git am` が失敗した場合は `git am --abort` で元に戻してから、エラー文を確認します。

### (4) 作業ブランチを作り、キットを入れる

```bash
git switch -c feature/v1.6.6
git am web-inspector-v1.6.6-agy-kit.patch
git log --oneline -3           # 先頭が「docs: v1.6.6 development kit for Antigravity CLI ...」ならOK
ls AGENTS.md scripts/dev/overnight.sh   # 両方あればOK
```

`feature/v1.6.6` が既にある場合（Gemini CLI 用キットを入れたブランチなど）は、いったん main に戻って `git branch -D feature/v1.6.6` で消してから、上を実行します。

### (5) パッチファイルをリポジトリの外へ移す

```bash
mkdir -p ~/patches && mv ./*.patch ~/patches/
git status                     # clean に戻ればOK
```

### (6) 事前チェック

```bash
bash scripts/dev/overnight.sh --check
```

`npm ci`・`npm test`・`npm run build` と権限の動作確認を行うため、5分ほどかかります。権限ルールはチェックの間だけ追加され、終わると自動で削除されます（以前の版のキットで手動で追加したルールも、ここで一緒に外れます）。全項目が `[OK]` になるまで、表示された対処をして再実行してください（§6 も参照）。

## 3. 夜間モードで開始する

```bash
bash scripts/dev/overnight.sh
```

これだけです。ターミナルは閉じずに、そのまま寝てください。スクリプトは次のように動きます。

1. 事前チェックをもう一度行い、問題がなければ T01 から順に進めます。タスクごとに次を繰り返します。
   1. agy を無人モードで起動し、そのタスクだけを実装させる（プロンプトは [TASK_PROMPT.md](./TASK_PROMPT.md)）
   2. スクリプトが `npm run spec:generate && npm test` を実行する
   3. 通ればコミットする（`[T03] <要約> (<指摘ID>)`）。落ちたら失敗の内容を渡して 1 に戻る（最大3回）
   4. 3回で直らなければ、変更を `~/web-inspector-overnight/<日時>/Txx-incomplete.patch` に保存して元に戻し、「未完了」と記録してコミットする
2. 全タスクの後、スクリプトが総合チェックを実行し、agy に完了報告書を作らせて（[REPORT_PROMPT.md](./REPORT_PROMPT.md)）、スクリプトがコミットします。
3. agy 自体がエラーで止まった場合（利用上限や通信エラー）は、15分おいて同じところからやり直します（全体で6回まで。それを超えたら中断し、翌日 `--resume` で続きから再開できます）。1回の起動は最長120分で打ち切り、時間切れのときは続きから次の回をやり直します（試行回数に数えます）。
4. 終了すると、タスクごとの結果・コミット一覧・静的チェックの結果を表示し、Mac の通知を出します。

### 速さの調整と、1タスクだけの試運転

事前チェックの最後に、agy の応答の速さ（1回考えるのにかかる秒数）が表示されます。平均60秒を超えると `[注意]` が出ます。その速さでは、一晩で12タスクが終わらない可能性があります。次の方法を、組み合わせて使えます。

| やりたいこと | コマンド |
| --- | --- |
| 1タスクだけ試して、所要時間を確かめる（完了報告書は作らない） | `ONLY="T01" bash scripts/dev/overnight.sh` |
| 使うモデルを指定する（名前は `agy models` で確認。High / Medium / Low の深さもモデル名で選ぶ） | `AGY_MODEL=gemini-3.8-flash-medium bash scripts/dev/overnight.sh` |
| 動作確認の制限時間を延ばす（初期値20分） | `PROBE_TIMEOUT=30m bash scripts/dev/overnight.sh --check` |
| 1回の起動の制限時間を変える（初期値120分） | `TASK_TIMEOUT=180m bash scripts/dev/overnight.sh` |

試運転で T01 をコミットした後に、本番を `bash scripts/dev/overnight.sh` で始めると、T01 は完了済みとして飛ばし、T02 から進めます。

## 4. 対話モードで進める場合（代替）

自分で見ながら進めたい場合は、§2 の (1)〜(5) の後に、リポジトリ直下で `agy` を起動し、次のスキル（スラッシュコマンド）を順に使います。対話モードでは、agy 自身がテストとコミットを行います（サンドボックスは使いません。権限ルールも追加しません）。


1. `/v166-start` … 前提確認と計画の提示。問題なければ「進めて」と入力します。
2. `/v166-task T01` 〜 `/v166-task T12` … 1タスクずつ実装・テスト・コミットします。途中で `/v166-verify` を使うと、残っている完了条件を確認できます。
3. `/v166-report` … 完了報告書の作成と最終チェック。

対話モードでは、コマンドを実行するたびに確認を求められます。内容を見て許可してください。push・ブランチ操作・`npm install`・`curl` などの許可を求められても、許可しないでください。

## 5. 朝の確認（人）

1. ターミナルの最後の表示（コミット一覧・未コミットの変更・静的チェック）を確認する。詳しいログは `~/web-inspector-overnight/<日時>/summary.txt` にあります。
2. `docs/dev/v1.6.6/COMPLETION_REPORT.md` を読む。特に §3（未完了のタスク）、§6（指示からの逸脱）、§8（人間の確認事項）を確認する。WORKLOG に「拒否されたコマンド」の記録があれば、その理由も確認する。
3. 報告書が無い、または未完了のタスクがある場合は、次のどちらかで続ける。
   - 続きを任せる: `bash scripts/dev/overnight.sh --resume`（未コミットの変更があっても続きから再開します）
   - 自分で見ながら直す: §4 の対話モードで `/v166-task Txx`
4. 自分の手元で総合チェックと E2E を実行し、報告書の数値と一致することを確認する: `node scripts/dev/check-v1.6.6.mjs --e2e`（Chrome のウィンドウが開きます）。
5. `npm run build` した `dist/` を Chrome の「パッケージ化されていない拡張機能を読み込む」で読み込み、次を目視で確認する。
   - 拡張を再読み込みした直後に、元から開いていたタブを調査すると、ヘッダー系の項目が「未観測」と表示される
   - `Server: Apache/2.4.41 (Ubuntu)` のページで「ディストリ版（バックポートの可能性）」と表示される（`npm run test-server` の `/distro-apache`）
   - Bootstrap だけのページ（`/bootstrap-only`）で Tailwind CSS が検出されない
   - ダッシュボードの調査履歴で「表示」「削除」が動く
6. `git diff main...feature/v1.6.6 -- PRIVACY_POLICY.md` を読み、文言を承認する（必要なら自分で直してコミット）。ストアのプライバシー欄・データ開示も合わせて更新する。
7. ここまで問題がなければ push して PR を作る。
   ```bash
   git push -u origin feature/v1.6.6
   gh pr create --base main --title "v1.6.6" --body-file docs/dev/v1.6.6/COMPLETION_REPORT.md
   ```
   CI が緑になったらマージします。v1.6.6 のストア提出は、事前準備手順書の運用に従ってください。
8. 念のため、権限ルールが外れていることを確認する: `node scripts/dev/agy-permissions.mjs --status` が `[NG] 不足しているルールが…` と表示されれば外れています（夜間スクリプトは終了時に自動で外します）。push 先が戻っていることも `git remote -v` で確認します（`DISABLED-during-v166-overnight-run` と表示されたら `git config --unset remote.origin.pushurl`）。

## 6. 事前チェックで [NG] が出たとき

| 表示 | 対処 |
| --- | --- |
| agy コマンドが見つかりません | §1 の 1 をやり直す。PATH に `~/.local/bin` があるか確認する |
| 電源アダプタに接続してください | 電源につなぐ |
| ブランチが ... です | `git switch feature/v1.6.6` |
| レビューパッチが main に入っていません | §2 (3) をやり直す |
| 旧キット（Gemini CLI 用）が残っています | §2 (4) の手順でブランチを作り直す |
| 未コミットの変更があります | `git status` で原因を確認する（パッチやメモの置き忘れが多い）。前回の続きなら `--resume` |
| 権限ルールに問題があります（permissions.ask の …） | 自分で入れた `ask` の `command(*)` などを、作業中だけ外す |
| 許可外の操作で無人実行が中断した | 表示されたメッセージの操作（どの権限か）を確認し、`probe.err` / `probe.jsonl` を保存して相談してください |
| agy が無人モードで応答しない | 対話モードで `agy` を起動し、ログイン状態と利用上限を確認する。ログは表示されたパスの `probe.err` |
| agy が最後の手順まで進まなかった | 応答が遅く、制限時間内に終わらなかった可能性があります。`PROBE_TIMEOUT=30m bash scripts/dev/overnight.sh --check` で再実行する |
| 許可したコマンド（git log）が実行できない／リポジトリ内のファイルを作成できない | サンドボックスの制限が想定と違います。`probe.jsonl` を保存して相談してください |
| 拒否したはずの git tag が実行された／リポジトリの外に書き込めてしまった／外部へ通信できてしまった | **夜間実行はしない。** agy の更新で権限やサンドボックスの仕様が変わった可能性があります。`probe.*` のログを保存して相談してください |

`npm test` や `npm run build` が失敗した場合は、表示されたログ（`~/web-inspector-overnight/<日時>/baseline-*.log`）を確認します。

## 同梱物

| ファイル | 役割 |
| --- | --- |
| `AGENTS.md`（リポジトリ直下） | エージェントが読む常設ルール（概要・コマンド・規約・禁止事項・夜間モード・完了の定義） |
| [INSTRUCTIONS.md](./INSTRUCTIONS.md) | 改修指示書（T01〜T12 の変更内容・テスト・完了条件、夜間モードの追加ルール） |
| [TASK_PROMPT.md](./TASK_PROMPT.md) | 夜間モードで、タスクごとに agy に渡すプロンプト（試行回数とテスト失敗の内容をスクリプトが差し込む） |
| [REPORT_PROMPT.md](./REPORT_PROMPT.md) | 夜間モードで、完了報告書を作らせるプロンプト |
| [REPORT_TEMPLATE.md](./REPORT_TEMPLATE.md) | 完了報告書のテンプレート |
| [WORKLOG.md](./WORKLOG.md) | エージェントが作業ごとに追記する作業記録 |
| [agy-permissions.json](./agy-permissions.json) | 許可・拒否のルール（コマンド、Web アクセス、変更禁止ファイル） |
| `scripts/dev/agy-permissions.mjs` | 上のルールをユーザー設定に追加・確認・削除するスクリプト（夜間スクリプトが自動で呼ぶ。対話モードでは手動で使う） |
| `.agents/skills/v166-*/SKILL.md` | 対話モード用のスキル（`/v166-start` など） |
| `scripts/dev/overnight.sh` | 夜間モードの起動スクリプト（事前チェック・権限の一時追加と動作確認・push 先の一時無効化・スリープ防止・自動再開・結果のまとめ） |
| `scripts/dev/check-v1.6.6.mjs` | 完了条件の機械チェック（結果を `check-result.json` に保存。C12 で作業キットの改変も検出） |
