#!/usr/bin/env python3
"""
Web Technology & Security Inspector
レビュー用パッケージ (ZIP) 作成スクリプト (scripts/create_review_package.py)

指定された Git ref (コミット / タグ / ブランチ) または作業ツリーから、
レビューに必要なドキュメント・ソースコード・設定ファイルのみを抽出して安全な ZIP を作成します。
"""

import argparse
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

# --- 含めるディレクトリ / ファイルのホワイトリスト ---
INCLUDE_PREFIXES = (
    "src/",
    "tests/",
    "scripts/",
    "docs/",
    "public/",
    "test-server/",
    ".github/workflows/",
)

INCLUDE_EXACT_FILES = {
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "tsconfig.node.json",
    "vite.config.ts",
    "data/nvd-snapshot.json",
    "README.md",
    "PRIVACY_POLICY.md",
}

# --- 除外するファイル・ディレクトリのブラックリスト ---
EXCLUDE_PREFIXES = (
    "node_modules/",
    "dist/",
    ".tmp/",
    ".git/",
    ".gemini/",
    ".venv/",
    "release/",
    "review/",
    "review-packages/",
)

EXCLUDE_PATTERNS = (
    ".env",
)


def run_cmd(cmd: list[str], cwd: Path | None = None) -> str:
    """コマンドを実行して標準出力を文字列として取得する"""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def run_cmd_bytes(cmd: list[str], cwd: Path | None = None) -> bytes:
    """コマンドを実行して標準出力をバイナリとして取得する"""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return result.stdout


def is_target_file(rel_path: str) -> bool:
    """指定された相対パスがZIPに含める対象かどうかを判定する"""
    norm_path = rel_path.replace("\\", "/")

    # 除外プレフィックスの判定
    for ex in EXCLUDE_PREFIXES:
        if norm_path.startswith(ex):
            return False

    # 除外パターンの判定 (.env, .env.local 等)
    filename = os.path.basename(norm_path)
    if filename.startswith(".env"):
        return False
    if norm_path.endswith(".zip"):
        return False

    # 含める完全一致ファイル
    if norm_path in INCLUDE_EXACT_FILES:
        return True

    # tsconfig* や vite.config* 等のパターン
    if filename.startswith("tsconfig") and filename.endswith(".json"):
        return True
    if filename.startswith("vite.config") and (filename.endswith(".ts") or filename.endswith(".js")):
        return True

    # 含めるプレフィックスディレクトリ
    for inc in INCLUDE_PREFIXES:
        if norm_path.startswith(inc):
            return True

    return False


def get_ref_metadata(ref: str, root_dir: Path) -> tuple[str, str]:
    """Git ref から 短縮コミットSHA、タグ名/バージョンを取得する"""
    # 短縮SHA (7桁) - アノテーション付きタグの場合はコミットオブジェクトのSHAを取得
    short_sha = run_cmd(["git", "rev-parse", "--short=7", f"{ref}^{{commit}}"], cwd=root_dir)

    # コミットに付けられたタグを取得 (優先)
    tags_out = run_cmd(["git", "tag", "--points-at", ref], cwd=root_dir)
    tag_name = ""
    if tags_out:
        for t in tags_out.splitlines():
            if t.strip().startswith("v"):
                tag_name = t.strip()
                break
        if not tag_name:
            tag_name = tags_out.splitlines()[0].strip()

    # コミット直指定ではなくタグ名そのものが ref として渡された場合
    if not tag_name:
        try:
            # ref 自体がタグ名か確認
            verify_tag = run_cmd(["git", "tag", "-l", ref], cwd=root_dir)
            if verify_tag:
                tag_name = verify_tag
        except Exception:
            pass

    # タグが見つからない場合は package.json の version を参照
    if not tag_name:
        try:
            pkg_content = run_cmd_bytes(["git", "show", f"{ref}:package.json"], cwd=root_dir)
            pkg_json = json.loads(pkg_content.decode("utf-8"))
            ver = pkg_json.get("version", "")
            if ver:
                tag_name = f"v{ver}" if not ver.startswith("v") else ver
        except Exception:
            tag_name = "snapshot"

    return short_sha, tag_name


def create_review_package(ref: str, output_dir: Path, root_dir: Path) -> Path:
    """指定された Git ref のファイル群からレビュー用 ZIP を作成する"""
    short_sha, tag_name = get_ref_metadata(ref, root_dir)

    # ZIP 名の決定: web-inspector-{tag}-{sha}.zip
    zip_filename = f"web-inspector-{tag_name}-{short_sha}.zip"
    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / zip_filename

    # 指定 ref の全ファイル一覧を取得
    all_files = run_cmd(["git", "ls-tree", "-r", "--name-only", ref], cwd=root_dir).splitlines()

    target_files = [f for f in all_files if is_target_file(f)]

    print(f"==================================================")
    print(f"📦 レビュー用 ZIP パッケージ作成")
    print(f"・対象 Git Ref: {ref}")
    print(f"・コミット SHA: {short_sha}")
    print(f"・バージョン/タグ: {tag_name}")
    print(f"・対象ファイル数: {len(target_files)} 件")
    print(f"・出力先: {zip_path}")
    print(f"==================================================")

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file_path in target_files:
            file_data = run_cmd_bytes(["git", "show", f"{ref}:{file_path}"], cwd=root_dir)
            zf.writestr(file_path, file_data)

    file_size_kb = zip_path.stat().st_size / 1024
    print(f"✅ ZIP 作成完了: {zip_path.name} ({file_size_kb:.1f} KB)")
    return zip_path


def main():
    parser = argparse.ArgumentParser(
        description="Web Technology & Security Inspector レビュー用 ZIP 作成ツール"
    )
    parser.add_argument(
        "ref",
        nargs="?",
        default="HEAD",
        help="対象とする Git ref (タグ、コミットハッシュ、ブランチ名)。省略時は HEAD",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="ZIP ファイルの出力先ディレクトリ (デフォルト: プロジェクトルートの review/ ディレクトリ)",
    )

    args = parser.parse_args()

    # プロジェクトルートディレクトリの特定
    script_dir = Path(__file__).resolve().parent
    root_dir = script_dir.parent

    try:
        # 指定された ref の実在確認
        run_cmd(["git", "rev-parse", "--verify", args.ref], cwd=root_dir)
    except subprocess.CalledProcessError:
        print(f"❌ エラー: 指定された Git ref '{args.ref}' が見つかりません。", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir).resolve() if args.output_dir else (root_dir / "review")
    create_review_package(args.ref, output_dir, root_dir)


if __name__ == "__main__":
    main()
