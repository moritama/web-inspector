#!/usr/bin/env bash
# =============================================================================
# Web Technology & Security Inspector — v1.6.6 夜間（無人）実行スクリプト (macOS)
#
# Antigravity CLI（agy）と、このスクリプトの分担で v1.6.6 を進める。
#   - agy:        サンドボックスの中で、1回に1タスクだけファイルを編集する（コミット・テストはしない）
#   - スクリプト: サンドボックスの外で、npm run spec:generate と npm test を実行し、通ればコミットする。
#                 落ちたら失敗の内容を渡して agy に直させる（最大 MAX_ATTEMPTS 回）。それでも直らなければ、
#                 変更をログに保存して元に戻し、「未完了」として記録・コミットして次のタスクへ進む
#   agy のサンドボックスは .git への書き込みと Node.js のテスト実行ができないため、この分担にしている。
#
# 安全のための仕組み
#   - agy は無人モード（-p）＋サンドボックス（--sandbox: 書き込みはリポジトリ内のみ・外部通信なし）で起動する。
#     --dangerously-skip-permissions は使わない（拒否ルールまで無効になるため）
#   - 権限ルール（docs/dev/v1.6.6/agy-permissions.json）は実行中だけユーザー設定に追加し、終了時に自動で削除する
#   - 実行中は push 先（remote.origin.pushurl）を無効な値にし、終了時に元に戻す
#   - 変更禁止のファイル（DB・CI・指示書など）への変更は、コミットの前にスクリプトが元に戻す
#   - このスクリプトは push しない。push は、人間が完了報告書を確認してから行う
#
# 使い方（リポジトリ直下で）:
#   bash scripts/dev/overnight.sh --check    # 事前チェックだけ行う（作業は始めない。権限の動作確認で agy を1回だけ短く起動する）
#   bash scripts/dev/overnight.sh            # 事前チェック → 夜間実行
#   bash scripts/dev/overnight.sh --resume   # 途中で止まった実行の再開（未コミット変更があっても続行）
# ログはリポジトリの外（~/web-inspector-overnight/<日時>/）に保存する。
# =============================================================================
set -uo pipefail

BRANCH="feature/v1.6.6"
DOC_DIR="docs/dev/v1.6.6"
TASK_PROMPT="${DOC_DIR}/TASK_PROMPT.md"
REPORT_PROMPT="${DOC_DIR}/REPORT_PROMPT.md"
REPORT_FILE="${DOC_DIR}/COMPLETION_REPORT.md"
WORKLOG="${DOC_DIR}/WORKLOG.md"
OUT_DIR=".agy-out"                       # agy とスクリプトのやり取り用（.git/info/exclude で無視する）
PUSH_BLOCK_URL="DISABLED-during-v166-overnight-run"
TASKS=(T01 T02 T03 T04 T05 T06 T07 T08 T09 T10 T11 T12)
# 一部のタスクだけ試す場合: ONLY="T01" bash scripts/dev/overnight.sh （完了報告書は作らない）
if [[ -n "${ONLY:-}" ]]; then read -r -a TASKS <<<"$ONLY"; fi
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"        # 1タスクあたりの最大試行回数（テスト失敗・中断を含む）
MAX_AGY_ERRORS="${MAX_AGY_ERRORS:-6}"    # agy 自体のエラー（利用上限・通信エラー等）の許容回数（全体で）
RETRY_WAIT_SEC="${RETRY_WAIT_SEC:-900}"  # agy 自体のエラーのときの再開までの待ち時間（秒）
TASK_TIMEOUT="${TASK_TIMEOUT:-120m}"     # 1回の agy 起動の上限時間（時間切れのときは、続きから次の回をやり直す）
PROBE_TIMEOUT="${PROBE_TIMEOUT:-20m}"    # 権限の動作確認の上限時間
SKIP_PROBE="${SKIP_PROBE:-0}"            # 1 にすると権限の動作確認を省略する
# 使うモデルを固定したい場合: AGY_MODEL=<agy models で表示される名前> bash scripts/dev/overnight.sh
AGY_ARGS=(--sandbox --mode accept-edits)
[[ -n "${AGY_MODEL:-}" ]] && AGY_ARGS+=(--model "$AGY_MODEL")
# 考える深さを下げて速くしたい場合: AGY_EFFORT=low（agy の --effort。モデルによって使える値が違う）
[[ -n "${AGY_EFFORT:-}" ]] && AGY_ARGS+=(--effort "$AGY_EFFORT")
export PATH="${HOME}/.local/bin:${PATH}"   # agy のインストール先
DENY_PATTERN='cannot prompt|auto-denied'
# 変更禁止（agy が変更していたらコミット前に元に戻す）
FORBIDDEN_RE='^(src/detection/advisory-db\.json|data/advisories/|scripts/advisories/|\.github/|scripts/cws-publish\.mjs|docs/REVIEW_v1\.6\.5\.md|AGENTS\.md|\.agents/|scripts/dev/|docs/dev/v1\.6\.6/(INSTRUCTIONS|TASK_PROMPT|REPORT_PROMPT|README|REPORT_TEMPLATE)\.md|docs/dev/v1\.6\.6/agy-permissions\.json|\.gitignore|\.agy-out/)'

MODE="run"
case "${1:-}" in
  --check) MODE="check" ;;
  --resume) MODE="resume" ;;
  "") ;;
  *) echo "不明なオプション: $1"; exit 2 ;;
esac

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "[NG] git リポジトリの中で実行してください"; exit 1; }
cd "$ROOT" || exit 1

STAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${HOME}/web-inspector-overnight/${STAMP}"
mkdir -p "$LOG_DIR"
SUMMARY="${LOG_DIR}/summary.txt"

ok=0; ng=0
pass() { echo "  [OK] $*" | tee -a "$SUMMARY"; ok=$((ok + 1)); }
fail() { echo "  [NG] $*" | tee -a "$SUMMARY"; ng=$((ng + 1)); }
info() { echo "$*" | tee -a "$SUMMARY"; }

# --- 後片付け（どの終わり方でも、権限ルールの削除と push 先の復元を行う）--------------
PERMS_INSTALLED=0
PUSH_BLOCKED=0
ORIG_PUSHURL=""
cleanup() {
  if [[ "$PUSH_BLOCKED" -eq 1 ]]; then
    if [[ -n "$ORIG_PUSHURL" ]]; then git config remote.origin.pushurl "$ORIG_PUSHURL"; else git config --unset remote.origin.pushurl 2>/dev/null; fi
    PUSH_BLOCKED=0
    echo "push 先を元に戻しました。" | tee -a "$SUMMARY"
  fi
  if [[ "$PERMS_INSTALLED" -eq 1 ]]; then
    node scripts/dev/agy-permissions.mjs --uninstall --quiet && echo "権限ルールを削除しました。" | tee -a "$SUMMARY"
    PERMS_INSTALLED=0
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

info "=== v1.6.6 夜間実行 事前チェック ($(date '+%Y-%m-%d %H:%M')) ==="
info "リポジトリ: $ROOT"
info "ログ: $LOG_DIR"

if [[ "$(git config --get remote.origin.pushurl)" == "$PUSH_BLOCK_URL" ]]; then
  git config --unset remote.origin.pushurl
  info "  （前回の実行で無効にした push 先が残っていたため、元に戻しました）"
fi

# --- 1. 実行環境 -----------------------------------------------------------
[[ "$(uname)" == "Darwin" ]] && pass "macOS で実行している" || fail "このスクリプトは macOS 専用です（caffeinate・pmset・通知を使うため）"
command -v caffeinate >/dev/null && pass "caffeinate がある" || fail "caffeinate が見つかりません"
command -v agy >/dev/null && pass "Antigravity CLI: $(agy --version 2>/dev/null | head -1)" || fail "agy コマンドが見つかりません（curl -fsSL https://antigravity.google/cli/install.sh | bash）"
info "  使用モデル: ${AGY_MODEL:-指定なし（agy の既定。AGY_MODEL=<agy models の名前> で指定できます）}"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[[ "$NODE_MAJOR" -ge 22 ]] && pass "Node.js $(node -v)" || fail "Node.js 22 以上が必要です（現在: $(node -v 2>/dev/null || echo なし)）"
if pmset -g batt 2>/dev/null | grep -q "AC Power"; then pass "電源アダプタに接続されている"; else fail "電源アダプタに接続してください（バッテリー駆動ではスリープや中断の恐れ）"; fi

# --- 2. ブランチとパッチ ----------------------------------------------------
CUR="$(git branch --show-current)"
[[ "$CUR" == "$BRANCH" ]] && pass "ブランチ $BRANCH にいる" || fail "ブランチが $CUR です（git switch $BRANCH）"
if git cat-file -e main:tests/review-v1.6.5-acceptance.test.ts 2>/dev/null && git cat-file -e main:scripts/advisories/build-db.mjs 2>/dev/null; then
  pass "レビューパッチが main に入っている"
else
  fail "レビューパッチが main に入っていません（main で git am web-inspector-review-v1.6.5.patch）"
fi
kit_ok=1
for f in AGENTS.md "${DOC_DIR}/INSTRUCTIONS.md" "$TASK_PROMPT" "$REPORT_PROMPT" "${DOC_DIR}/agy-permissions.json" scripts/dev/agy-permissions.mjs scripts/dev/check-v1.6.6.mjs; do
  [[ -f "$f" ]] || { fail "キットのファイルがありません: $f（git am web-inspector-v1.6.6-agy-kit.patch）"; kit_ok=0; }
done
[[ "$kit_ok" -eq 1 ]] && pass "Antigravity CLI 用キットが入っている"
if [[ -f GEMINI.md || -d .gemini ]]; then fail "旧キット（Gemini CLI 用）の GEMINI.md / .gemini が残っています。ブランチを作り直してください（README §2）"; fi
if [[ "$MODE" != "resume" ]]; then
  if [[ -z "$(git status --porcelain --untracked-files=normal)" ]]; then pass "作業ツリーがクリーン"; else fail "未コミットの変更があります（git status で確認。前回の続きなら --resume）"; fi
  if [[ -f "$REPORT_FILE" ]]; then fail "完了報告書が既にあります（作業済みの可能性。確認してください）"; else pass "完了報告書はまだない"; fi
fi

# agy とのやり取り用フォルダ（コミットされないように .git/info/exclude に入れる）
mkdir -p "$OUT_DIR"
grep -qxF "/${OUT_DIR}/" .git/info/exclude 2>/dev/null || echo "/${OUT_DIR}/" >> .git/info/exclude

# --- 3. 依存とベースライン ---------------------------------------------------
if [[ "$ng" -eq 0 ]]; then
  info "依存のインストールとベースライン測定（数分かかります）..."
  if npm ci --no-audit --no-fund >"${LOG_DIR}/npm-ci.log" 2>&1; then pass "npm ci"; else fail "npm ci に失敗（${LOG_DIR}/npm-ci.log）"; fi
  if npm test >"${LOG_DIR}/baseline-test.log" 2>&1; then
    pass "npm test: $(grep -E 'Tests +' "${LOG_DIR}/baseline-test.log" | tail -1 | sed 's/^ *//')"
  else
    fail "npm test が失敗（${LOG_DIR}/baseline-test.log）。--resume の場合は前回の途中状態が原因の可能性"
    [[ "$MODE" == "resume" ]] && { ng=$((ng - 1)); info "  （--resume のため続行。最初のタスクで直させます）"; }
  fi
  if npm run build >"${LOG_DIR}/baseline-build.log" 2>&1; then pass "npm run build"; else fail "npm run build が失敗（${LOG_DIR}/baseline-build.log）"; fi
fi

# --- 4. 権限ルールを一時的に追加（終了時に自動で削除）-----------------------------
if [[ "$ng" -eq 0 ]]; then
  if node scripts/dev/agy-permissions.mjs --install --quiet >"${LOG_DIR}/permissions.log" 2>&1; then
    PERMS_INSTALLED=1
    if node scripts/dev/agy-permissions.mjs --status >>"${LOG_DIR}/permissions.log" 2>&1; then
      pass "権限ルールを一時的に追加した（終了時に自動で削除）"
    else
      fail "権限ルールに問題があります: $(tail -2 "${LOG_DIR}/permissions.log" | tr '\n' ' ')"
    fi
  else
    fail "権限ルールを追加できません: $(tail -3 "${LOG_DIR}/permissions.log" | tr '\n' ' ')"
  fi
fi

# --- agy の起動（結果を AGY_RESULT に入れる: ok / denied / interrupted / error）-------------
AGY_RESULT=""
run_agy() {  # $1=プロンプト $2=ログ名 $3=上限時間 [$4=出力形式]
  local out="${LOG_DIR}/$2.jsonl" err="${LOG_DIR}/$2.err"
  caffeinate -i -s agy -p "$1" --output-format "${4:-stream-json}" --print-timeout "$3" "${AGY_ARGS[@]}" >"$out" 2>"$err"
  local code=$?
  if grep -Eq "$DENY_PATTERN" "$err"; then AGY_RESULT="denied"
  elif grep '"event":"result"' "$out" | grep -q '"finished_reason":"print_timeout"'; then AGY_RESULT="timeout"
  elif [[ "$code" -eq 0 ]] && grep -q '"event":"result"' "$out"; then AGY_RESULT="ok"
  elif grep -q 'stream was interrupted' "$err"; then AGY_RESULT="interrupted"
  else AGY_RESULT="error"; fi
  info "    agy: ${AGY_RESULT} (exit=${code}, $2)"
}

# --- 5. 権限の動作確認（agy を短く1回起動して、実際に確かめる）---------------------
#   できること: 許可したコマンド（git log）、リポジトリ内のファイルの作成（ファイル編集ツール）
#   できないこと: 拒否したコマンド（git tag / curl）、リポジトリ外への書き込み、外部への通信
#   ※ エージェントが自分の判断で実行しなかった場合も「実行されなかった」として OK になる（どちらでも安全側）。
run_probe() {
  local tag="agy-probe-${STAMP}" outside="${HOME}/agy-probe-${STAMP}.txt" head prompt
  local out="${LOG_DIR}/probe.jsonl"
  head="$(git rev-parse HEAD)"
  rm -f "${OUT_DIR}/probe.txt"
  prompt="これは権限設定の動作確認です。v1.6.6 の作業ではありません。
次の手順を、書いてあるとおりに上から1つずつ行ってください（コマンドには cd などを前に付けず、そのまま実行してください）。拒否されたり失敗したりしても、再試行や別の方法は試さず、次へ進んでください。
1. シェルで git log -1 --format=%H を実行する
2. ファイル編集ツールで、ファイル ${OUT_DIR}/probe.txt を作り、内容を PROBE_FILE_OK の1行にする
3. シェルで git tag ${tag} を実行する
4. シェルで touch ${outside} を実行する
5. シェルで node -e \"fetch('https://example.com').then(r=>console.log('NET', 'REACHED', r.status)).catch(()=>console.log('NET', 'BLOCKED'))\" を実行する
6. シェルで curl -sI https://example.com を実行する
最後に PROBE_DONE とだけ書いて終了してください。"
  info "権限の動作確認（agy を短く起動します。2〜5分）..."
  run_agy "$prompt" probe "$PROBE_TIMEOUT"
  local reached_last=0
  grep -q '"CommandLine":"curl -sI' "$out" && reached_last=1
  case "$AGY_RESULT" in
    ok|timeout)
      if grep '"event":"result"' "$out" | grep -q 'PROBE_DONE' || [[ "$reached_last" -eq 1 ]]; then
        pass "agy が無人モード（-p）で最後の手順まで進んだ"
      else
        fail "agy が最後の手順まで進まなかった（${AGY_RESULT}。${out}。応答が遅い場合は PROBE_TIMEOUT=30m で再実行）"
      fi ;;
    denied) fail "許可外の操作で無人実行が中断した: $(grep -E "$DENY_PATTERN" "${LOG_DIR}/probe.err" | head -1 | cut -c1-200)" ;;
    interrupted) fail "agy の通信が途中で切れた（agy 側の一時的なエラー。少し待ってから --check をやり直してください）" ;;
    *) fail "agy が無人モードで応答しない（ログイン切れ・利用上限の可能性。${LOG_DIR}/probe.err を参照。対話モードで agy を起動してログインを確認）" ;;
  esac
  if grep -q "$head" "$out"; then pass "許可したコマンド（git log）は実行できる"; else fail "許可したコマンド（git log）が実行できない（${out}）"; fi
  if grep -q 'PROBE_FILE_OK' "${OUT_DIR}/probe.txt" 2>/dev/null; then
    pass "リポジトリ内のファイルを作成・編集できる"
  else
    fail "リポジトリ内のファイルを作成できない（このままでは実装できません。${out}）"
  fi
  rm -f "${OUT_DIR}/probe.txt"
  if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    fail "拒否したはずの git tag が実行された（権限ルールが効いていない。夜間実行は危険です）"
    git tag -d "$tag" >/dev/null 2>&1
  else
    pass "拒否したコマンド（git tag）は実行されなかった"
  fi
  if [[ -e "$outside" ]]; then
    fail "リポジトリの外に書き込めてしまった（サンドボックスが効いていません。夜間実行は危険です）"
    rm -f "$outside"
  else
    pass "リポジトリの外への書き込みはできなかった"
  fi
  if grep -Eq 'NET REACHED|HTTP/[0-9.]+ [0-9]{3}' "$out"; then
    fail "外部（example.com）へ通信できてしまった（サンドボックスで通信が止まっていません）"
  else
    pass "外部への通信はできなかった"
  fi
  # 応答の速さ（1回考えるのにかかった秒数）。遅いと一晩で全タスクが終わらない
  local speed
  speed="$(node -e '
    const ls = require("fs").readFileSync(process.argv[1], "utf8").split("\n");
    const d = [];
    for (const l of ls) { try { const e = JSON.parse(l).step_update; if (e && e.step_type === "agent_response" && e.state === "DONE" && e.duration_seconds) d.push(e.duration_seconds); } catch {} }
    if (d.length) process.stdout.write(String(Math.round(d.reduce((a, b) => a + b, 0) / d.length)));
  ' "$out")"
  if [[ -n "$speed" ]]; then
    if [[ "$speed" -gt 60 ]]; then
      info "  [注意] agy の応答が遅いです（1回考えるのに平均 ${speed} 秒）。この速さだと、一晩で全タスクが終わらない可能性があります。"
      info "         AGY_EFFORT=low や、速いモデル（AGY_MODEL=<agy models の名前>）を試すか、ONLY=\"T01\" で1タスクだけ試して所要時間を確かめてください。"
    else
      info "  （参考: agy の応答は1回あたり平均 ${speed} 秒）"
    fi
  fi
}
if [[ "$ng" -eq 0 ]]; then
  if [[ "$SKIP_PROBE" == "1" ]]; then info "  （SKIP_PROBE=1 のため権限の動作確認を省略）"; else run_probe; fi
fi

info "--- 事前チェック: OK ${ok} / NG ${ng}"
if [[ "$ng" -gt 0 ]]; then info "NG があるため作業を開始しません。"; exit 1; fi
if [[ "$MODE" == "check" ]]; then info "--check のため、ここで終了します。"; exit 0; fi

# =============================================================================
# 6. 夜間実行
# =============================================================================
if git remote get-url origin >/dev/null 2>&1; then
  ORIG_PUSHURL="$(git config --get remote.origin.pushurl || true)"
  git config remote.origin.pushurl "$PUSH_BLOCK_URL"
  PUSH_BLOCKED=1
  info "実行中は push 先を無効にしました（終了時に元に戻します）。"
fi

fill_prompt() {  # $1=テンプレート $2=タスク $3=回数 $4=状況
  TASK="$2" ATTEMPT="$3" FEEDBACK="$4" node -e '
    const fs = require("fs");
    let t = fs.readFileSync(process.argv[1], "utf8");
    for (const k of ["TASK", "ATTEMPT", "FEEDBACK"]) t = t.split("{{" + k + "}}").join(process.env[k]);
    process.stdout.write(t);
  ' "$1"
}

result_field() {  # $1=フィールド名（.agy-out/result.json から1行で取り出す）
  node -e '
    let r = {};
    try { r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); } catch {}
    const v = String(r[process.argv[2]] ?? "").replace(/[\r\n]+/g, " ").trim();
    process.stdout.write(v.slice(0, process.argv[2] === "note" ? 500 : 80));
  ' "${OUT_DIR}/result.json" "$1"
}

changed_paths() { git status --porcelain --untracked-files=all | cut -c4- | sed 's/.* -> //'; }
has_changes() { [[ -n "$(changed_paths)" ]]; }

REVERTED=""
revert_forbidden() {
  REVERTED=""
  local p
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    if [[ "$p" =~ $FORBIDDEN_RE ]] && [[ "$p" != "${OUT_DIR}/"* ]]; then
      if git cat-file -e "HEAD:$p" 2>/dev/null; then git restore --source=HEAD --staged --worktree -- "$p"; else rm -rf -- "$p"; fi
      REVERTED="${REVERTED} ${p}"
    fi
  done < <(changed_paths)
  [[ -n "$REVERTED" ]] && info "    変更禁止のファイルへの変更を元に戻しました:${REVERTED}"
}

run_tests() {  # $1=ログ名。spec:generate → npm test（サンドボックスの外）
  local log="${LOG_DIR}/$1.log"
  { npm run spec:generate && npm test; } >"$log" 2>&1
}

commit_all() {  # $1=メッセージ1行目 $2=本文
  git add -A
  git -c commit.gpgsign=false commit -q -m "$1" -m "$2"
}

task_done() { git log --format=%s main..HEAD | grep -q "^\[$1\]"; }

AGY_ERRORS=0
STOP_ALL=0
TASK_RESULTS=()

run_task() {  # $1=タスクID
  local t="$1" attempt=1 feedback status summary ids note
  rm -f "${OUT_DIR}/test-failure.txt"
  if has_changes; then
    feedback="作業ツリーに、前回の実行が途中で止まったときの変更が残っています。\`git status\` と \`git diff\` で確認し、タスク ${t} の続きとして仕上げてください（タスク ${t} と関係のない変更は元に戻してください）。"
  else
    feedback="前のタスクまでは完了・記録済みです（\`git log --oneline main..HEAD\` で確認できます）。"
  fi
  while [[ "$attempt" -le "$MAX_ATTEMPTS" ]]; do
    info "  [${t}] ${attempt} 回目 開始 $(date '+%H:%M')"
    rm -f "${OUT_DIR}/result.json"
    run_agy "$(fill_prompt "$TASK_PROMPT" "$t" "$attempt" "$feedback")" "${t}-${attempt}" "$TASK_TIMEOUT"
    if [[ "$AGY_RESULT" == "error" || "$AGY_RESULT" == "interrupted" ]]; then
      AGY_ERRORS=$((AGY_ERRORS + 1))
      if [[ "$AGY_ERRORS" -gt "$MAX_AGY_ERRORS" ]]; then
        info "  agy のエラーが ${MAX_AGY_ERRORS} 回を超えたため、作業を中断します（利用上限の可能性。--resume で再開できます）"
        STOP_ALL=1; return
      fi
      info "  agy がエラーで終了しました（${AGY_ERRORS}/${MAX_AGY_ERRORS}）。${RETRY_WAIT_SEC} 秒後に同じ回をやり直します。"
      caffeinate -i -s sleep "$RETRY_WAIT_SEC"
      continue
    fi
    revert_forbidden
    local extra=""
    [[ -n "$REVERTED" ]] && extra=" 変更禁止のファイル（${REVERTED# }）への変更は、スクリプトが元に戻しました。これらは変更しないでください。"
    if [[ "$AGY_RESULT" == "timeout" && ! -f "${OUT_DIR}/result.json" ]]; then
      feedback="前回の実行は、時間切れ（${TASK_TIMEOUT}）で途中で終わりました。作業ツリーには前回の変更が残っています。\`git status\` と \`git diff\` で確認し、タスク ${t} の続きを仕上げてください。調べ直しは最小限にしてください。${extra}"
      info "    時間切れ（${TASK_TIMEOUT}）。続きから次の回をやり直します。"
      attempt=$((attempt + 1)); continue
    fi
    if [[ "$AGY_RESULT" == "denied" ]]; then
      feedback="前回の実行は、無人モードで確認できない操作（リポジトリ外のファイルの読み書き、Web アクセスなど）を行おうとしたため中断しました。agy のメッセージ: $(grep -E "$DENY_PATTERN" "${LOG_DIR}/${t}-${attempt}.err" | head -1 | cut -c1-300)。同じ操作は行わず、リポジトリ内のファイルだけで続けてください。作業ツリーには前回の変更が残っています。${extra}"
      attempt=$((attempt + 1)); continue
    fi
    status="$(result_field status)"; summary="$(result_field summary)"; ids="$(result_field ids)"; note="$(result_field note)"
    if ! has_changes; then
      if [[ "$status" == "incomplete" ]]; then break; fi
      feedback="前回の実行では、ファイルが変更されていませんでした。タスク ${t} を実装し、WORKLOG と ${OUT_DIR}/result.json を書いてください。${extra}"
      attempt=$((attempt + 1)); continue
    fi
    info "    テスト（サンドボックスの外）: npm run spec:generate && npm test"
    if run_tests "${t}-${attempt}-test"; then
      local head="[${t}] ${summary:-タスク ${t}}${ids:+ (${ids})}"
      [[ "$status" == "partial" ]] && head="[${t}] （一部）${summary:-タスク ${t}}${ids:+ (${ids})}"
      commit_all "$head" "夜間モード（agy が実装、スクリプトがテスト・コミット）。試行 ${attempt} 回目。status=${status:-不明}${note:+ / note: ${note}}"
      info "  [${t}] コミットしました: $(git log -1 --format='%h %s')"
      TASK_RESULTS+=("${t} コミット済み $(git log -1 --format=%h) ${status:-不明}")
      return
    fi
    tail -n 200 "${LOG_DIR}/${t}-${attempt}-test.log" >"${OUT_DIR}/test-failure.txt"
    info "    テストが失敗しました（${LOG_DIR}/${t}-${attempt}-test.log）"
    feedback="前回の変更で、スクリプトが実行した \`npm run spec:generate && npm test\` が失敗しました。失敗の内容（末尾200行）は \`${OUT_DIR}/test-failure.txt\` にあります。読んで原因を直してください。作業ツリーには前回の変更が残っています。受け入れテストの期待値は変えないでください。${extra}"
    attempt=$((attempt + 1))
  done
  # 未完了: 変更をログに保存して元に戻し、記録をコミットする
  note="$(result_field note)"
  if has_changes; then
    git add -A && git diff --cached >"${LOG_DIR}/${t}-incomplete.patch"; git reset -q
    git restore --source=HEAD --staged --worktree -- . 2>/dev/null; git clean -fdq
    info "  [${t}] 未完了。変更は ${LOG_DIR}/${t}-incomplete.patch に保存して元に戻しました。"
  fi
  {
    echo ""
    echo "## ${t} 未完了（夜間スクリプトによる自動記録）  ($(date '+%Y-%m-%d %H:%M'))"
    echo "- 結果: ${MAX_ATTEMPTS} 回試しても npm test が通らなかった、または実装できなかったため、変更を元に戻した"
    echo "- 変更の保存先（リポジトリ外）: ${LOG_DIR}/${t}-incomplete.patch"
    echo "- agy の最後のメモ: ${note:-なし}"
    echo "- 人間に判断してほしいこと: 上記パッチとテストのログ（${LOG_DIR}/${t}-*-test.log）を確認し、対応方針を決める"
  } >>"$WORKLOG"
  commit_all "[${t}] 未完了（自動記録）" "夜間モード。${MAX_ATTEMPTS} 回の試行で完了しなかったため、変更を元に戻して記録のみコミット。"
  TASK_RESULTS+=("${t} 未完了 $(git log -1 --format=%h)")
}

info ""
info "=== 夜間実行 開始 $(date '+%Y-%m-%d %H:%M')（タスクごとに: agy が実装 → スクリプトがテスト・コミット） ==="
info "朝までこのターミナルを閉じないでください。蓋を閉じるとスリープする機種があるため、蓋は開けたままにしてください。"
for t in "${TASKS[@]}"; do
  if task_done "$t"; then info "  [${t}] 完了済み（スキップ）"; TASK_RESULTS+=("${t} コミット済み（前回まで） $(git log --format='%h %s' main..HEAD | grep "\[${t}\]" | head -1 | cut -d' ' -f1)"); continue; fi
  run_task "$t"
  [[ "$STOP_ALL" -eq 1 ]] && break
done

# --- 7. 完了報告書 -------------------------------------------------------------
if [[ -n "${ONLY:-}" ]]; then
  info ""
  info "ONLY=${ONLY} のため、完了報告書は作りません。"
elif [[ "$STOP_ALL" -eq 0 ]] && ! git log --format=%s main..HEAD | grep -q "完了報告書"; then
  info ""
  info "=== 完了報告書の作成 $(date '+%H:%M') ==="
  info "  総合チェック（サンドボックスの外で実行。数分かかります）..."
  node scripts/dev/check-v1.6.6.mjs >"${LOG_DIR}/check-before-report.log" 2>&1
  printf '%s\n' ${TASK_RESULTS[@]+"${TASK_RESULTS[@]}"} >"${OUT_DIR}/tasks.txt"
  git log --oneline main..HEAD >"${OUT_DIR}/git-log.txt"
  git diff --stat main...HEAD >"${OUT_DIR}/diffstat.txt"
  grep -E '\[(PASS|FAIL)\] R0' "${LOG_DIR}/check-before-report.log" >"${OUT_DIR}/test-summary.txt"
  {
    echo "OS: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
    echo "Node.js: $(node -v) / npm: $(npm -v)"
    echo "Antigravity CLI: $(agy --version 2>/dev/null | head -1) / model: ${AGY_MODEL:-agy の既定（未指定）}${AGY_EFFORT:+ / effort: ${AGY_EFFORT}}"
  } >"${OUT_DIR}/env.txt"
  report_try=1
  while [[ "$report_try" -le "$MAX_ATTEMPTS" ]]; do
    run_agy "$(cat "$REPORT_PROMPT")" "report-${report_try}" "$TASK_TIMEOUT"
    [[ -f "$REPORT_FILE" ]] && break
    report_try=$((report_try + 1))
    [[ "$AGY_RESULT" == "error" || "$AGY_RESULT" == "interrupted" ]] && caffeinate -i -s sleep "$RETRY_WAIT_SEC"
  done
  revert_forbidden
  if [[ -f "$REPORT_FILE" ]]; then
    info "  総合チェックをやり直します（報告書の作成後）..."
    node scripts/dev/check-v1.6.6.mjs >"${LOG_DIR}/check-after-report.log" 2>&1
    commit_all "[T12] 完了報告書" "夜間モード。報告書は agy が作成し、総合チェックと commit はスクリプトが実行。"
    info "  完了報告書をコミットしました: $(git log -1 --format='%h %s')"
  else
    info "  完了報告書を作成できませんでした（${LOG_DIR}/report-*.err を参照）。"
  fi
fi

# --- 8. 結果のまとめ ----------------------------------------------------------
info ""
info "=== 結果 ($(date '+%Y-%m-%d %H:%M')) ==="
info "タスク:"
printf '  %s\n' ${TASK_RESULTS[@]+"${TASK_RESULTS[@]}"} | tee -a "$SUMMARY"
info "コミット:"
git log --oneline main..HEAD | tee -a "$SUMMARY"
info "未コミットの変更:"
git status --short | tee -a "$SUMMARY"
node scripts/dev/check-v1.6.6.mjs --static >"${LOG_DIR}/check-static.log" 2>&1
tail -1 "${LOG_DIR}/check-static.log" | tee -a "$SUMMARY"
grep -E "^\s+\[FAIL\]" "${LOG_DIR}/check-static.log" | tee -a "$SUMMARY"
if git ls-files --error-unmatch "${DOC_DIR}/check-result.json" >/dev/null 2>&1; then
  git checkout -- "${DOC_DIR}/check-result.json"
else
  rm -f "${DOC_DIR}/check-result.json"
fi
if [[ -f "$REPORT_FILE" ]]; then
  info "完了報告書: $ROOT/$REPORT_FILE"
else
  info "完了報告書は作成されていません。ログを確認し、必要なら bash scripts/dev/overnight.sh --resume で再開してください。"
fi
info "ログ一式: $LOG_DIR"
info "次の作業: ${DOC_DIR}/README.md の「朝の確認」の手順へ（push は確認後に人が行う）"
cleanup
osascript -e 'display notification "v1.6.6 夜間作業が終了しました" with title "Web Inspector"' >/dev/null 2>&1 || true
