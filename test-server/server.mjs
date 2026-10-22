/**
 * Web Technology & Security Inspector
 * テスト検証用ローカルHTTPサーバー (test-server/server.mjs)
 *
 * 以下のテストシグナルをシミュレートします:
 * - サーバーヘッダー: Server: Apache/2.4.58 (Unix)
 * - 言語ヘッダー: X-Powered-By: PHP/8.2.14
 * - CMS特徴: WordPress 6.4.2 (meta generator, wp-content, wp-includes)
 * - フロントエンド特徴: React, Next.js (__NEXT_DATA__, data-reactroot), Tailwind CSS
 * - Cookie: PHPSESSID (未保護: Secureなし, HttpOnlyなし), test_secure_cookie (保護)
 * - セキュリティ設定: HSTSなし, CSP unsafe-inlineあり, X-Content-Type-Optionsなし
 */

import http from 'node:http';

const PORT = 3000;

const sampleHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="WordPress 6.4.2">
  <title>Web Inspector 検証用テストページ</title>
  <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
  <script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script>
</head>
<body class="flex flex-col min-h-screen bg-gray-100 text-gray-900 p-8">
  <header class="bg-white shadow rounded-lg p-6 mb-6">
    <h1 class="text-2xl font-bold text-blue-600">Web Inspector テスト検証ページ</h1>
    <p class="text-gray-600 mt-2">
      このページは、Web Inspector拡張機能の動作検証（PHP, Apache, WordPress, React, セキュリティ診断等）を行うためのモック環境です。
    </p>
  </header>

  <main class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <section class="bg-white p-6 rounded-lg shadow" id="root" data-reactroot="">
      <h2 class="text-xl font-semibold mb-4">React & Next.js コンポーネント (モック)</h2>
      <p>DOM上に [data-reactroot] および __NEXT_DATA__ スクリプトが埋め込まれています。</p>
      <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"site":"Web Inspector Test"}}}</script>
    </section>

    <section class="bg-white p-6 rounded-lg shadow">
      <h2 class="text-xl font-semibold mb-4">テスト用Cookie & ヘッダー情報</h2>
      <ul class="list-disc pl-5 space-y-2 text-sm text-gray-700">
        <li><strong>Server:</strong> Apache/2.4.58</li>
        <li><strong>X-Powered-By:</strong> PHP/8.2.14</li>
        <li><strong>Set-Cookie:</strong> PHPSESSID (Secureなし, HttpOnlyなし)</li>
        <li><strong>CSP:</strong> 'unsafe-inline' 緩和設定あり</li>
        <li><strong>HSTS:</strong> 未設定（HTTP環境のため正常動作をテスト）</li>
      </ul>
    </section>
  </main>
</body>
</html>`;

const server = http.createServer((req, res) => {
  // セキュリティテスト用ヘッダーの付与
  res.setHeader('Server', 'Apache/2.4.58 (Unix)');
  res.setHeader('X-Powered-By', 'PHP/8.2.14');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");
  res.setHeader('Set-Cookie', [
    'PHPSESSID=mock_session_token_12345; Path=/; SameSite=Lax',
    'auth_token=sample_jwt_token; Path=/; Secure; HttpOnly; SameSite=Strict',
  ]);
  res.setHeader('Content-Type', 'text/html; charset=UTF-8');

  res.writeHead(200);
  res.end(sampleHtml);
});

server.listen(PORT, () => {
  console.log(`\n=================================================`);
  console.log(` Web Inspector 検証用テストサーバー起動完了!`);
  console.log(` URL: http://localhost:${PORT}`);
  console.log(`=================================================\n`);
});
