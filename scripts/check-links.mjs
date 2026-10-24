/**
 * Web Technology & Security Inspector
 * Markdown 相対リンク実在性検査スクリプト (scripts/check-links.mjs)
 */
import fs from 'node:fs';
import path from 'node:path';

let hasError = false;

function checkFile(file) {
  const content = fs.readFileSync(file, 'utf8');
  const dir = path.dirname(file);
  const re = /\]\((?!https?:|mailto:|#)([^)]+)\)/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    const rawTarget = m[1].split('#')[0].trim();
    if (!rawTarget) continue;
    const target = path.resolve(dir, rawTarget);
    if (!fs.existsSync(target)) {
      console.error(`[BROKEN LINK] ${file} -> ${rawTarget} (resolved: ${target})`);
      hasError = true;
    }
  }
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'dist' && entry.name !== 'release') {
        walk(full);
      }
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      checkFile(full);
    }
  }
}

console.log('[check-links] ドキュメント内の相対リンクを検証中...');
walk('docs');
checkFile('README.md');

if (hasError) {
  console.error('[check-links] リンク切れが検出されました。');
  process.exit(1);
} else {
  console.log('[check-links] ✅ すべての相対リンクが実在することを確認しました。');
}
