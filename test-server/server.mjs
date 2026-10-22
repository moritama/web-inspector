/**
 * Web Technology & Security Inspector
 * テスト検証用ローカルHTTPサーバー (test-server/server.mjs) - Version 1.1.0
 *
 * 以下のテストシグナルをシミュレートします:
 * - JavaScript実行時情報 (MAIN World):
 *   - jQuery 3.6.0 (window.jQuery.fn.jquery)
 *   - Bootstrap 4.3.1 (jQuery.fn.modal.Constructor.VERSION)
 * - CSSアセット (ADD-02):
 *   - /lib/bootstrap-4.3.1/css/bootstrap.min.css (Bootstrap 4.3.1)
 * - バージョン整合性 (ADD-03):
 *   - CSS 4.3.1 vs JS 4.3.1 (一致: match)
 * - EOL判定 (ADD-04):
 *   - Bootstrap 4.x -> EOL (2023-01)
 * - サーバーヘッダー: Server: Apache/2.4.58 (Unix), X-Powered-By: PHP/8.2.14
 * - セキュリティ設定: HSTSなし, CSP unsafe-inlineあり, Cookie属性課題
 */

import http from 'node:http';

const PORT = 3000;

const sampleHtml = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="WordPress 6.4.2">
  <title>Web Inspector v1.1 検証用テストページ</title>
  
  <!-- CSSアセット (Bootstrap 4.3.1) -->
  <link rel="stylesheet" href="/lib/bootstrap-4.3.1/css/bootstrap.min.css">
  <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">

  <!-- jQuery & Bootstrap JS (モック実行時スクリプト) -->
  <script>
    // jQuery 3.6.0 モック
    window.jQuery = function() {};
    window.jQuery.fn = {
      jquery: "3.6.0",
      modal: {
        Constructor: {
          VERSION: "4.3.1" // Bootstrap 4.3.1 モック
        }
      }
    };
    window.$ = window.jQuery;
  </script>
</head>
<body class="flex flex-col min-h-screen bg-gray-100 text-gray-900 p-8">
  <header class="bg-white shadow rounded-lg p-6 mb-6">
    <h1 class="text-2xl font-bold text-blue-600">Web Inspector v1.1 テスト検証ページ</h1>
    <p class="text-gray-600 mt-2">
      このページは、JavaScript実行時情報（jQuery 3.6.0, Bootstrap 4.3.1）、CSS解析（bootstrap-4.3.1）、
      バージョン整合性、EOLサポート判定、CVE照合の動作確認用モック環境です。
    </p>
  </header>

  <main class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <section class="bg-white p-6 rounded-lg shadow" id="root" data-reactroot="">
      <h2 class="text-xl font-semibold mb-4">ライブラリバージョン検証 (v1.1)</h2>
      <ul class="list-disc pl-5 space-y-2 text-sm text-gray-700">
        <li><strong>window.jQuery.fn.jquery:</strong> 3.6.0 (実行時)</li>
        <li><strong>Bootstrap JS:</strong> 4.3.1 (実行時)</li>
        <li><strong>Bootstrap CSS:</strong> 4.3.1 (URLパス: /lib/bootstrap-4.3.1/css/bootstrap.min.css)</li>
        <li><strong>整合性:</strong> CSS 4.3.1 == JS 4.3.1 (一致 / match)</li>
        <li><strong>EOL判定:</strong> Bootstrap 4.x (EOL 2023-01)</li>
      </ul>
      <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"site":"Web Inspector Test v1.1"}}}</script>
    </section>

    <section class="bg-white p-6 rounded-lg shadow">
      <h2 class="text-xl font-semibold mb-4">テスト用Cookie & ヘッダー情報</h2>
      <ul class="list-disc pl-5 space-y-2 text-sm text-gray-700">
        <li><strong>Server:</strong> Apache/2.4.58</li>
        <li><strong>X-Powered-By:</strong> PHP/8.2.14</li>
        <li><strong>Set-Cookie:</strong> PHPSESSID (未保護)</li>
        <li><strong>CSP:</strong> 'unsafe-inline' あり</li>
        <li><strong>HSTS:</strong> 未設定</li>
      </ul>
    </section>
  </main>
</body>
</html>`;

const server = http.createServer((req, res) => {
  // レスポンスヘッダー
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
  console.log(` Web Inspector v1.1 検証用テストサーバー起動完了!`);
  console.log(` URL: http://localhost:${PORT}`);
  console.log(`=================================================\n`);
});
