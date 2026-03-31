// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config



import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'DEADCATS',
  tagline: "Cybersecurity research, binary exploitation, and digital forensics from DEADCATS.",
  favicon: 'img/0_medium.png',

  // Set the production url of your site here
  url: 'https://deadcats.space/',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'DEADCATS', // Usually your GitHub org/user name.
  projectName: 'DEADCATS', // Usually your repo name.

  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'ignore',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
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
          breadcrumbs: false,
          sidebarPath: './sidebars.js',
          routeBasePath: '/',
        },
        blog: {
          blogTitle: 'Research',
          blogDescription: 'Cybersecurity research, binary exploitation, forensics, and technical analysis from DEADCATS.',
          postsPerPage: 10,
          routeBasePath: '/', // Serves blog at the site root
          showReadingTime: true,
          blogSidebarTitle: 'All posts',
          blogSidebarCount: 'ALL',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },
      
      // Replace with your project's social card
      // image: 'img/docusaurus-social-card.jpg',
      navbar: {
        title: 'DEADCATS',
        logo: {
          alt: 'My Site Logo',
          src: 'img/0_medium.png',
        },

        items: [
          {
            type: 'dropdown',
            label: 'DEADCATS',
            position: 'right',
            items: [
              {
                label: 'CTFtime',
                href: 'https://ctftime.org/team/367609',
              },
              
            ],
          },

          {
            type: 'dropdown',
            label: 'Team Members',
            position: 'right',
            items: [
              {
                label: 'At0m',
                href: 'https://ctftime.org/team/367609',
              },
              {
                label: 'Sephiroth',
                href: 'https://ctftime.org/team/367609',
              },
              {
                label: '0x0w1z',
                href: 'https://0x0w1z.tech/',
              },
              {
                label: '404Buddha',
                href: 'https://ctftime.org/team/367609',
              },
              {
                label: 'Ken',
                href: 'https://ctftime.org/team/367609',
              },
              {
                label: 'P0u',
                href: 'https://nidanpoudel.com.np/',
              },
              {
                label: 'Ebi',
                href: 'https://ctftime.org/team/367609',
              },
              {
                label: '4w4647',
                href: 'https://ctftime.org/team/367609',
              },
            ],
          },

          {
            type: 'dropdown',
            label: 'Contact Us',
            position: 'right',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/Diethylazodicarboxylate',
              }, 
              {
                label: 'Twitter/X',
                href: 'https://x.com/0xdeadcats',
              }, 	
            ],
          },

        ],
      },
      prism: {
        theme: prismThemes.oneDark,
      },
      algolia: {
          // The application ID provided by Algolia
        appId: 'XUM92KL2IK',
          // Public API key: it is safe to commit it
        apiKey: '7ed7f707a437c68890cd68c2f51b0949',
        indexName: 'writeups-kunull',
        // contextualSearch: false,
        typoTolerance: false,
        maxResultsPerGroup: 9999,
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 5,
      },
    }),
  
};

export default config;
