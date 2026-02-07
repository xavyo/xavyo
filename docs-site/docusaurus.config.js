// @ts-check

import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'xavyo Documentation',
  tagline: 'Identity Governance & Administration Platform',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://docs.xavyo.io',
  baseUrl: '/',

  organizationName: 'xavyo',
  projectName: 'xavyo-idp',

  onBrokenLinks: 'warn',

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          docItemComponent: '@theme/ApiItem',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  plugins: [
    [
      'docusaurus-plugin-openapi-docs',
      {
        id: 'api',
        docsPluginId: 'default',
        config: {
          xavyo: {
            specPath: '../docs/api/openapi.json',
            outputDir: 'docs/reference/api',
            sidebarOptions: {
              groupPathsBy: 'tag',
              categoryLinkSource: 'auto',
            },
          },
        },
      },
    ],
  ],

  themes: ['docusaurus-theme-openapi-docs', '@docusaurus/theme-mermaid'],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/docusaurus-social-card.jpg',
      colorMode: {
        defaultMode: 'light',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'xavyo',
        logo: {
          alt: 'xavyo Logo',
          src: 'img/logo.svg',
        },
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'docsSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            type: 'docSidebar',
            sidebarId: 'apiSidebar',
            position: 'left',
            label: 'API Reference',
          },
          {
            href: 'https://github.com/xavyo/xavyo-idp',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              {
                label: 'Getting Started',
                to: '/docs/getting-started/what-is-xavyo',
              },
              {
                label: 'Admin Guides',
                to: '/docs/guides/admin/tenant-setup',
              },
              {
                label: 'Developer Guides',
                to: '/docs/guides/developer/api-overview',
              },
            ],
          },
          {
            title: 'Reference',
            items: [
              {
                label: 'API Reference',
                to: '/docs/reference/api/xavyo-api',
              },
              {
                label: 'Error Codes',
                to: '/docs/reference/error-codes',
              },
              {
                label: 'Glossary',
                to: '/docs/reference/glossary',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/xavyo/xavyo-idp',
              },
            ],
          },
        ],
        copyright: `Copyright \u00a9 ${new Date().getFullYear()} xavyo. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['bash', 'json', 'rust', 'toml'],
      },
    }),
};

export default config;
