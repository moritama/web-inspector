/**
 * 脆弱性DBパイプラインのテスト用フィクスチャ (オフライン)
 * 実在の CVE は公開情報どおりの値、"CVE-2099-*" / "GHSA-aaaa-*" は架空のテスト専用IDです。
 */

export const fixtureCatalog = {
  schemaVersion: 1,
  defaults: { nvd: { publishedSince: '2018-01-01', minCvss: 7.0, includeKevAlways: true } },
  products: {
    jquery: { aliases: ['jquery'], osv: [{ ecosystem: 'npm', name: 'jquery' }], eol: { slug: 'jquery' } },
    react: {
      aliases: ['react', 'reactjs'],
      osv: [{ ecosystem: 'npm', name: 'react' }, { ecosystem: 'npm', name: 'react-dom' }],
      eol: { slug: 'react', supportedLatestCycles: 1 },
    },
    nginx: { aliases: ['nginx'], nvd: { targets: ['f5:nginx', 'nginx:nginx'], autoIngest: true }, eol: { slug: 'nginx' } },
    php: { aliases: ['php'], nvd: { targets: ['php:php'], autoIngest: false }, eol: { slug: 'php' } },
    lodash: { aliases: ['lodash'], osv: [{ ecosystem: 'npm', name: 'lodash' }], eol: { static: true } },
  },
};

export const fixtureCurated = {
  schemaVersion: 1,
  products: {
    jquery: {
      advisories: [
        {
          cve: 'CVE-2020-11023',
          range: '>= 1.0.3, < 3.5.0',
          cvssScore: 6.1,
          title: 'XSS in jQuery.htmlPrefilter even with sanitizers',
          fixedVersion: '3.5.0',
          advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11023',
          verifiedAt: '2026-10-25',
          scoreSource: 'nvd@nist.gov (Primary)',
        },
      ],
    },
    php: {
      advisories: [
        {
          cve: 'CVE-2024-4577',
          range: '< 8.1.29 || >= 8.2.0, < 8.2.20 || >= 8.3.0, < 8.3.8',
          cvssScore: 9.8,
          title: 'PHP-CGI argument injection (Windows)',
          summary: '該当の可能性あり (条件: Windows上のPHP-CGI)。<script>alert(1)</script>',
          fixedVersion: '8.1.29 / 8.2.20 / 8.3.8',
          advisoryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
          verifiedAt: '2026-10-25',
          scoreSource: 'nvd@nist.gov (Primary)',
        },
      ],
    },
    lodash: {
      advisories: [],
      staticEol: [
        { cycle: '4.x', eolDate: null, status: 'Supported' },
        { cycle: '3.x', eolDate: '2016-01-12', status: 'EOL' },
      ],
    },
  },
  excludes: [{ id: 'GHSA-aaaa-bbbb-0003', product: 'jquery', reason: 'テスト用除外' }],
};

const osvJquery = {
  package: { ecosystem: 'npm', name: 'jquery' },
  fetchedAt: '2026-10-26T00:00:00.000Z',
  vulns: [
    {
      id: 'GHSA-gxr4-xjj5-5px2',
      aliases: ['CVE-2020-11022'],
      summary: 'Potential XSS vulnerability in jQuery',
      published: '2020-04-29T22:18:55Z',
      modified: '2025-01-01T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N' }],
      databaseSeverity: 'MODERATE',
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11022', 'javascript:alert(1)', 'http://insecure.example/'],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '1.2.0' }, { fixed: '3.5.0' }] }] }],
    },
    {
      id: 'GHSA-jpcq-cgw6-v4j6',
      aliases: ['CVE-2020-11023'],
      summary: 'Potential XSS vulnerability in jQuery',
      published: '2020-04-29T22:18:55Z',
      modified: '2025-01-01T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N' }],
      databaseSeverity: 'MODERATE',
      references: [],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '1.0.3' }, { fixed: '3.5.0' }] }] }],
    },
    {
      id: 'GHSA-aaaa-bbbb-0001',
      aliases: [],
      summary: 'Fictional <img src=x onerror=alert(1)> issue without CVE',
      published: '2024-01-01T00:00:00Z',
      modified: '2024-01-02T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' }],
      databaseSeverity: 'HIGH',
      references: [],
      affected: [
        { ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.12.0' }, { introduced: '2.0.0' }, { fixed: '2.2.5' }] }] },
      ],
    },
    {
      id: 'GHSA-aaaa-bbbb-0002',
      aliases: ['CVE-2099-0002'],
      summary: 'Fictional issue scored only with CVSS v4',
      published: '2025-01-01T00:00:00Z',
      modified: '2025-01-01T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }],
      databaseSeverity: 'CRITICAL',
      references: [],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.0.0' }] }] }],
    },
    {
      id: 'GHSA-aaaa-bbbb-0003',
      aliases: [],
      summary: 'Fictional excluded issue',
      published: '2025-01-01T00:00:00Z',
      modified: '2025-01-01T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      databaseSeverity: 'CRITICAL',
      references: [],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.0.0' }] }] }],
    },
    {
      id: 'GHSA-aaaa-bbbb-0004',
      aliases: ['CVE-2099-0004'],
      summary: 'Fictional withdrawn advisory',
      published: '2025-01-01T00:00:00Z',
      modified: '2025-01-01T00:00:00Z',
      withdrawn: '2025-02-01T00:00:00Z',
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
      databaseSeverity: 'CRITICAL',
      references: [],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] }],
    },
  ],
};

const osvLodash = {
  package: { ecosystem: 'npm', name: 'lodash' },
  fetchedAt: '2026-10-26T00:00:00.000Z',
  vulns: [
    {
      id: 'GHSA-aaaa-bbbb-0005',
      aliases: ['CVE-2099-0005'],
      summary: 'Fictional lodash issue with no fix',
      published: '2025-05-01T00:00:00Z',
      modified: '2025-05-01T00:00:00Z',
      withdrawn: null,
      severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' }],
      databaseSeverity: 'MODERATE',
      references: [],
      affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '4.0.0' }, { last_affected: '4.17.21' }] }] }],
    },
  ],
};

const exactVersions = Array.from({ length: 30 }, (_, i) => `1.${10 + Math.floor(i / 10)}.${i % 10}`);

const nvdNginx = {
  target: 'f5:nginx',
  fetchedAt: '2026-10-26T00:00:00.000Z',
  cves: [
    {
      id: 'CVE-2021-23017',
      published: '2021-06-01',
      lastModified: '2024-11-21',
      vulnStatus: 'Modified',
      description: 'A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite.',
      cvss: { score: 7.7, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H', source: 'nvd@nist.gov (Primary)', secondaryScore: null, secondarySource: null },
      matches: [{ criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', vsi: '0.6.18', vee: '1.20.1' }],
      conditions: [],
      references: ['https://nginx.org/en/security_advisories.html'],
    },
    {
      id: 'CVE-2099-1001',
      published: '2025-03-01',
      lastModified: '2025-03-02',
      vulnStatus: 'Analyzed',
      description: 'Fictional nginx module issue affecting enumerated versions when running on a specific OS.',
      cvss: { score: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', source: 'nvd@nist.gov (Primary)', secondaryScore: 9.8, secondarySource: 'cna@example.org' },
      matches: exactVersions.map((v) => ({ criteria: `cpe:2.3:a:f5:nginx:${v}:*:*:*:*:*:*:*` })),
      conditions: ['OS: microsoft windows'],
      references: [],
    },
    {
      id: 'CVE-2099-1002',
      published: '2025-03-01',
      lastModified: '2025-03-02',
      vulnStatus: 'Rejected',
      description: 'Rejected reason: duplicate.',
      cvss: { score: 9.8, vector: null, source: 'nvd@nist.gov (Primary)', secondaryScore: null, secondarySource: null },
      matches: [{ criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*', vee: '1.25.0' }],
      conditions: [],
      references: [],
    },
    {
      id: 'CVE-2099-1003',
      published: '2016-01-01',
      lastModified: '2016-01-02',
      vulnStatus: 'Analyzed',
      description: 'Fictional old low-severity issue that should be filtered out.',
      cvss: { score: 5.3, vector: null, source: 'nvd@nist.gov (Primary)', secondaryScore: null, secondarySource: null },
      matches: [{ criteria: 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', vei: '1.9.0' }],
      conditions: [],
      references: [],
    },
  ],
};

const nvdPhp = {
  target: 'php:php',
  fetchedAt: '2026-10-26T00:00:00.000Z',
  cves: [
    {
      id: 'CVE-2024-4577',
      published: '2024-06-09',
      lastModified: '2025-01-01',
      vulnStatus: 'Analyzed',
      description: 'In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, ...',
      cvss: { score: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', source: 'nvd@nist.gov (Primary)', secondaryScore: null, secondarySource: null },
      matches: [
        { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vsi: '8.1.0', vee: '8.1.29' },
        { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vsi: '8.2.0', vee: '8.2.20' },
        { criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', vsi: '8.3.0', vee: '8.3.8' },
      ],
      conditions: ['OS: microsoft windows'],
      references: [],
    },
  ],
};

export const fixtureUpstream = {
  manifest: { schemaVersion: 1, fetchedAt: '2026-10-26T00:00:00.000Z', sources: { 'osv:npm:jquery': { status: 'ok', count: 6 } } },
  osv: { 'npm:jquery': osvJquery, 'npm:lodash': osvLodash },
  nvd: { 'f5:nginx': nvdNginx, 'php:php': nvdPhp },
  eol: {
    react: {
      slug: 'react',
      fetchedAt: '2026-10-26T00:00:00.000Z',
      cycles: [
        { cycle: '19', releaseDate: '2024-12-05', eol: false, support: true },
        { cycle: '18', releaseDate: '2022-03-29', eol: false, support: false },
        { cycle: '17', releaseDate: '2020-10-20', eol: false, support: false },
      ],
    },
    nginx: {
      slug: 'nginx',
      fetchedAt: '2026-10-26T00:00:00.000Z',
      cycles: [
        { cycle: '1.30', releaseDate: '2026-04-14', eol: false },
        { cycle: '1.29', releaseDate: '2025-06-24', eol: '2026-05-13' },
        { cycle: '1.28', releaseDate: '2025-04-23', eol: '2026-04-14' },
      ],
    },
    jquery: {
      slug: 'jquery',
      fetchedAt: '2026-10-26T00:00:00.000Z',
      cycles: [
        { cycle: '4', releaseDate: '2026-01-17', eol: false, support: true },
        { cycle: '3', releaseDate: '2016-06-09', eol: false, support: '2026-01-17' },
        { cycle: '2', releaseDate: '2013-04-18', eol: true },
        { cycle: '1', releaseDate: '2006-08-26', eol: true },
      ],
    },
  },
  kev: { catalogVersion: '2026.10.24', dateReleased: '2026-10-24', count: 1, items: { 'CVE-2020-11023': '2025-01-23' } },
  nvdScores: {
    'CVE-2020-11022': {
      fetchedAt: '2026-10-26T00:00:00.000Z',
      cvss: { score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', source: 'nvd@nist.gov (Primary)', secondaryScore: 6.9, secondarySource: 'security-advisories@github.com' },
    },
  },
};

/** NVD API 2.0 の生レコード (compactNvdCve のテスト用。架空) */
export const rawNvdCve = {
  id: 'CVE-2099-2001',
  published: '2025-06-01T10:00:00.000',
  lastModified: '2025-06-02T10:00:00.000',
  vulnStatus: 'Analyzed',
  descriptions: [
    { lang: 'es', value: 'Descripción' },
    { lang: 'en', value: 'Fictional PHP-CGI issue on Windows. More details follow.' },
  ],
  metrics: {
    cvssMetricV31: [
      { source: 'security@php.net', type: 'Secondary', cvssData: { baseScore: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' } },
      { source: 'nvd@nist.gov', type: 'Primary', cvssData: { baseScore: 8.1, vectorString: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' } },
    ],
  },
  configurations: [
    {
      operator: 'AND',
      nodes: [
        { operator: 'OR', negate: false, cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*', versionStartIncluding: '8.1.0', versionEndExcluding: '8.1.29' }] },
        { operator: 'OR', negate: false, cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }] },
      ],
    },
    {
      nodes: [{ operator: 'OR', negate: false, cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:otherv:otherp:*:*:*:*:*:*:*:*', versionEndExcluding: '1.0' }] }],
    },
  ],
  references: [{ url: 'https://www.php.net/ChangeLog-8.php' }, { url: 'https://evil.example/' }],
};
