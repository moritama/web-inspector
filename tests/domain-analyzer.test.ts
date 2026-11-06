/**
 * Web Technology & Security Inspector
 * 外部通信先・ドメイン解析単体テスト (tests/domain-analyzer.test.ts)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  analyzeExternalConnections,
  collectLoadedResourceUrls,
  determinePartyType,
  guessServiceCategory,
  parsePslText,
  parsePublicSuffixAndRegistrableDomain,
  parseRegistrableDomain,
  PUBLIC_SUFFIX_EXCEPTIONS,
  PUBLIC_SUFFIX_LIST,
  PUBLIC_SUFFIX_WILDCARDS,
} from '../src/security/domain-analyzer';

describe('Domain Analyzer (Rev.2.1 IMP-11)', () => {
  describe('parsePublicSuffixAndRegistrableDomain', () => {
    it('一般的なgTLDのeTLD+1を正しく判定できること', () => {
      const res1 = parsePublicSuffixAndRegistrableDomain('example.com');
      expect(res1.registrableDomain).toBe('example.com');
      expect(res1.publicSuffix).toBe('com');

      const res2 = parsePublicSuffixAndRegistrableDomain('sub.app.example.com');
      expect(res2.registrableDomain).toBe('example.com');
      expect(res2.publicSuffix).toBe('com');
    });

    it('複合ccTLD (.co.jp, .com.au, .gov.uk等) を正しく認識してeTLD+1を判定できること', () => {
      const resJp = parsePublicSuffixAndRegistrableDomain('sub.corp.example.co.jp');
      expect(resJp.registrableDomain).toBe('example.co.jp');
      expect(resJp.publicSuffix).toBe('co.jp');

      const resAu = parsePublicSuffixAndRegistrableDomain('portal.service.com.au');
      expect(resAu.registrableDomain).toBe('service.com.au');
      expect(resAu.publicSuffix).toBe('com.au');

      const resUk = parsePublicSuffixAndRegistrableDomain('data.gov.uk');
      expect(resUk.registrableDomain).toBe('data.gov.uk');
      expect(resUk.publicSuffix).toBe('gov.uk');
    });

    it('Private Suffix (.github.io, .cloudfront.net等) の登録可能ドメインを認識できること', () => {
      const resGh = parsePublicSuffixAndRegistrableDomain('myproject.github.io');
      expect(resGh.registrableDomain).toBe('myproject.github.io');
      expect(resGh.publicSuffix).toBe('github.io');

      const resCf = parsePublicSuffixAndRegistrableDomain('d12345.cloudfront.net');
      expect(resCf.registrableDomain).toBe('d12345.cloudfront.net');
      expect(resCf.publicSuffix).toBe('cloudfront.net');
    });

    it('ローカルホストやIPアドレスを適切に処理できること', () => {
      const resLocal = parsePublicSuffixAndRegistrableDomain('localhost');
      expect(resLocal.registrableDomain).toBe('localhost');
      expect(resLocal.publicSuffix).toBe('');

      const resIp = parsePublicSuffixAndRegistrableDomain('192.168.1.100');
      expect(resIp.registrableDomain).toBe('192.168.1.100');
      expect(resIp.publicSuffix).toBe('');
    });

    it('日本の地域型JPドメイン (foo.tokyo.jp) と属性型JPドメイン (a.b.example.co.jp) の登録可能ドメインを正しく判定できること (T13 / DOC-12)', () => {
      const resTokyo = parseRegistrableDomain('foo.tokyo.jp');
      expect(resTokyo.registrableDomain).toBe('foo.tokyo.jp');
      expect(resTokyo.publicSuffix).toBe('tokyo.jp');

      const resTokyoSub = parseRegistrableDomain('www.foo.tokyo.jp');
      expect(resTokyoSub.registrableDomain).toBe('foo.tokyo.jp');
      expect(resTokyoSub.publicSuffix).toBe('tokyo.jp');

      const resCoJp = parseRegistrableDomain('a.b.example.co.jp');
      expect(resCoJp.registrableDomain).toBe('example.co.jp');
      expect(resCoJp.publicSuffix).toBe('co.jp');

      // 都道府県・政令指定都市の例外ルール (!metro.tokyo.jp, *.kawasaki.jp, !city.kawasaki.jp)
      const resMetro = parseRegistrableDomain('www.metro.tokyo.jp');
      expect(resMetro.registrableDomain).toBe('metro.tokyo.jp');
      expect(resMetro.publicSuffix).toBe('tokyo.jp');

      const resKawasakiWard = parseRegistrableDomain('sub.nakahara.kawasaki.jp');
      expect(resKawasakiWard.registrableDomain).toBe('sub.nakahara.kawasaki.jp');
      expect(resKawasakiWard.publicSuffix).toBe('nakahara.kawasaki.jp');

      const resKawasakiCity = parseRegistrableDomain('www.city.kawasaki.jp');
      expect(resKawasakiCity.registrableDomain).toBe('city.kawasaki.jp');
      expect(resKawasakiCity.publicSuffix).toBe('kawasaki.jp');
    });

    it('小さな PSL フィクスチャ (tests/fixtures/psl.fixture.dat) を読み込んで PSL ルールを正しく解釈できること (T13 / DOC-12)', () => {
      const fixturePath = path.resolve(__dirname, 'fixtures', 'psl.fixture.dat');
      const fixtureText = fs.readFileSync(fixturePath, 'utf-8');
      const parsed = parsePslText(fixtureText);

      expect(parsed.suffixes).toContain('tokyo.jp');
      expect(parsed.suffixes).toContain('co.jp');
      expect(parsed.wildcards).toContain('kawasaki.jp');
      expect(parsed.exceptions).toContain('metro.tokyo.jp');
      expect(parsed.exceptions).toContain('city.kawasaki.jp');

      expect(parseRegistrableDomain('foo.tokyo.jp', fixtureText)).toEqual({
        isIpOrLocal: false,
        publicSuffix: 'tokyo.jp',
        registrableDomain: 'foo.tokyo.jp',
      });
      expect(parseRegistrableDomain('a.b.example.co.jp', fixtureText)).toEqual({
        isIpOrLocal: false,
        publicSuffix: 'co.jp',
        registrableDomain: 'example.co.jp',
      });
      expect(parseRegistrableDomain('www.metro.tokyo.jp', fixtureText)).toEqual({
        isIpOrLocal: false,
        publicSuffix: 'tokyo.jp',
        registrableDomain: 'metro.tokyo.jp',
      });
      expect(parseRegistrableDomain('portal.ward.kawasaki.jp', fixtureText)).toEqual({
        isIpOrLocal: false,
        publicSuffix: 'ward.kawasaki.jp',
        registrableDomain: 'portal.ward.kawasaki.jp',
      });
      expect(parseRegistrableDomain('www.city.kawasaki.jp', fixtureText)).toEqual({
        isIpOrLocal: false,
        publicSuffix: 'kawasaki.jp',
        registrableDomain: 'city.kawasaki.jp',
      });

      // 生成済みモジュールにも主要ルールが含まれていること
      expect(PUBLIC_SUFFIX_LIST).toContain('tokyo.jp');
      expect(PUBLIC_SUFFIX_WILDCARDS).toContain('kawasaki.jp');
      expect(PUBLIC_SUFFIX_EXCEPTIONS).toContain('city.kawasaki.jp');
    });
  });

  describe('determinePartyType', () => {
    it('同一eTLD+1の場合はfirst-partyと判定されること', () => {
      const party = determinePartyType('api.example.com', 'https://www.example.com/login');
      expect(party).toBe('first-party');

      const partyJp = determinePartyType('assets.sub.company.co.jp', 'https://company.co.jp/');
      expect(partyJp).toBe('first-party');
    });

    it('異なるeTLD+1の場合はthird-partyと判定されること', () => {
      const party = determinePartyType('cdn.jsdelivr.net', 'https://www.example.com/');
      expect(party).toBe('third-party');
    });

    it('ローカルホストまたはIPアドレスの場合はlocalと判定されること', () => {
      const party = determinePartyType('localhost', 'https://example.com/');
      expect(party).toBe('local');

      const partyIp = determinePartyType('127.0.0.1', 'https://example.com/');
      expect(partyIp).toBe('local');
    });
  });

  describe('guessServiceCategory', () => {
    it('CDNサービスをcdnと判定すること', () => {
      expect(guessServiceCategory('cdnjs.cloudflare.com')).toBe('cdn');
      expect(guessServiceCategory('cdn.jsdelivr.net')).toBe('cdn');
      expect(guessServiceCategory('unpkg.com')).toBe('cdn');
    });

    it('アクセス解析サービスをanalyticsと判定すること', () => {
      expect(guessServiceCategory('www.google-analytics.com')).toBe('analytics');
      expect(guessServiceCategory('www.googletagmanager.com')).toBe('analytics');
      expect(guessServiceCategory('www.clarity.ms')).toBe('analytics');
    });

    it('Webフォントサービスをfontsと判定すること', () => {
      expect(guessServiceCategory('fonts.googleapis.com')).toBe('fonts');
      expect(guessServiceCategory('use.typekit.net')).toBe('fonts');
    });

    it('広告サービスをadvertisingと判定すること', () => {
      expect(guessServiceCategory('pagead2.googlesyndication.com')).toBe('advertising');
      expect(guessServiceCategory('securepubads.g.doubleclick.net')).toBe('advertising');
    });

    it('SNSサービスをsocialと判定すること', () => {
      expect(guessServiceCategory('platform.twitter.com')).toBe('social');
      expect(guessServiceCategory('connect.facebook.net')).toBe('social');
    });

    it('APIサービスをapiと判定すること', () => {
      expect(guessServiceCategory('api.stripe.com')).toBe('api');
      expect(guessServiceCategory('api.github.com')).toBe('api');
    });

    it('未知のホストはotherと判定すること', () => {
      expect(guessServiceCategory('some-internal-server.corp')).toBe('other');
    });
  });

  describe('analyzeExternalConnections', () => {
    it('複数のリソースURLを集約して接続先サマリーを正しく集計できること', () => {
      const targetUrl = 'https://portal.example.co.jp/dashboard';
      const resourceUrls = [
        'https://portal.example.co.jp/styles.css',
        'https://static.example.co.jp/logo.png',
        'https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.min.js',
        'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX',
        'https://fonts.googleapis.com/css2?family=Roboto',
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
      ];

      const analysis = analyzeExternalConnections(targetUrl, resourceUrls);

      expect(analysis.totalConnections).toBe(6); // portal, static, cdnjs, gtm, fonts, jsdelivr
      expect(analysis.firstPartyCount).toBe(2); // portal & static (共に example.co.jp)
      expect(analysis.thirdPartyCount).toBe(4); // cdnjs, gtm, fonts, jsdelivr

      expect(analysis.categoryBreakdown.cdn).toBe(3); // cdnjs, jsdelivr, static.example.co.jp
      expect(analysis.categoryBreakdown.analytics).toBe(1); // gtm
      expect(analysis.categoryBreakdown.fonts).toBe(1); // fonts

      const cdnjsItem = analysis.connections.find((c) => c.hostname === 'cdnjs.cloudflare.com');
      expect(cdnjsItem).toBeDefined();
      expect(cdnjsItem?.partyType).toBe('third-party');
      expect(cdnjsItem?.registrableDomain).toBe('cloudflare.com');
      expect(cdnjsItem?.category).toBe('cdn');
      expect(cdnjsItem?.resourceCount).toBe(1);
    });

    it('無効なURLや空配列が渡されても安全に空の結果を返すこと', () => {
      const analysis = analyzeExternalConnections('https://example.com/', ['invalid-url', '']);
      expect(analysis.totalConnections).toBe(0);
      expect(analysis.firstPartyCount).toBe(0);
      expect(analysis.thirdPartyCount).toBe(0);
      expect(analysis.connections).toEqual([]);
    });

    it('v1.7.1 T05: sampleUrls にクエリ文字列やフラグメントが含まれる場合、stripUrlQueryAndFragment でマスクされること', () => {
      const analysis = analyzeExternalConnections('https://www.drupal.org/', [
        'https://www.drupal.org/',
        'https://www.drupal.org/files/advagg_css/css__abc.css?token=SECRET_TOKEN_123#section',
      ]);
      expect(analysis.totalConnections).toBe(1);
      expect(analysis.connections[0].sampleUrls).toEqual([
        'https://www.drupal.org/',
        'https://www.drupal.org/files/advagg_css/css__abc.css',
      ]);
      expect(JSON.stringify(analysis.connections[0].sampleUrls)).not.toContain('SECRET_TOKEN_123');
    });
  });

  describe('v1.7.1 T05: collectLoadedResourceUrls と T04 公開サイトスナップショット回帰検証', () => {
    it('collectLoadedResourceUrls がページ本体・Resource Timing・DOMリソースを集約して重複を除去すること', () => {
      const urls = collectLoadedResourceUrls('https://app.example.test/page?foo=1', {
        url: 'https://app.example.test/page?foo=1',
        title: 'Test',
        scriptUrls: ['/js/app.js', 'https://cdn.example.test/lib.js'],
        linkUrls: [{ rel: 'stylesheet', href: '/css/style.css' }],
        domResourceUrls: ['https://img.example.test/logo.png'],
        resourceEntries: [
          { url: 'https://app.example.test/js/app.js', initiatorType: 'script' },
          { url: 'https://api.example.test/v1/data', initiatorType: 'fetch' },
        ],
        metaTags: [],
        domMarkers: [],
        htmlSnippets: [],
        mixedContent: [],
        cookiesFromDocument: [],
        cssAssets: [],
      });

      expect(urls).toEqual([
        'https://app.example.test/page',
        'https://app.example.test/js/app.js',
        'https://api.example.test/v1/data',
        'https://cdn.example.test/lib.js',
        'https://app.example.test/css/style.css',
        'https://img.example.test/logo.png',
      ]);
    });

    it('T04 の全スナップショット（testasp.vulnweb.com、testaspnet.vulnweb.com、demo.testfire.net、http.badssl.com、www.drupal.org ほか）で通信先が 0 件にならないこと', () => {
      const snapshotsDir = path.resolve(__dirname, 'fixtures', 'snapshots');
      const requiredHosts = [
        'testasp.vulnweb.com',
        'testaspnet.vulnweb.com',
        'demo.testfire.net',
        'http.badssl.com',
        'www.drupal.org',
      ];

      const files = fs
        .readdirSync(snapshotsDir)
        .filter((f) => f.endsWith('.json'))
        .sort();

      for (const reqHost of requiredHosts) {
        expect(files).toContain(`${reqHost}.json`);
      }

      for (const file of files) {
        const snapPath = path.join(snapshotsDir, file);
        const snap = JSON.parse(fs.readFileSync(snapPath, 'utf-8')) as {
          url: string;
          finalUrl?: string;
          resourceTiming?: Array<{ name: string; initiatorType?: string }>;
        };
        const pageUrl = snap.finalUrl || snap.url;
        const resourceUrls = collectLoadedResourceUrls(pageUrl, {
          url: pageUrl,
          title: '',
          metaTags: [],
          scriptUrls: [],
          linkUrls: [],
          domMarkers: [],
          htmlSnippets: [],
          mixedContent: [],
          cookiesFromDocument: [],
          cssAssets: [],
          resourceEntries: (snap.resourceTiming || []).map((e) => ({
            url: e.name,
            initiatorType: e.initiatorType || 'other',
          })),
        });
        const analysis = analyzeExternalConnections(pageUrl, resourceUrls);

        expect(analysis.totalConnections).toBeGreaterThanOrEqual(1);
        expect(analysis.connections.length).toBeGreaterThanOrEqual(1);

        const selfHostname = new URL(pageUrl).hostname.toLowerCase();
        const selfConn = analysis.connections.find((c) => c.hostname === selfHostname);
        expect(selfConn).toBeDefined();
        expect(selfConn?.resourceCount).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
