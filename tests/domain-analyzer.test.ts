/**
 * Web Technology & Security Inspector
 * 外部通信先・ドメイン解析単体テスト (tests/domain-analyzer.test.ts)
 */

import { describe, expect, it } from 'vitest';
import {
  analyzeExternalConnections,
  determinePartyType,
  guessServiceCategory,
  parsePublicSuffixAndRegistrableDomain,
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
  });
});
