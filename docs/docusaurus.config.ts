import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const config: Config = {
  title: "Crashwise Documentation",
  tagline: "AI-Powered Security Analysis Platform",
  favicon: "img/favicon.ico",

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // Production url of documentation
  url: "https://docs.crashwise.ai",
  // The /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/",
  trailingSlash: false,

  // GitHub pages deployment config.
  organizationName: "YahyaToubali",
  projectName: "Crashwise",
  deploymentBranch: "gh-pages",

  onBrokenLinks: "throw",

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: "warn",
    },
  },

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl:
            "https://github.com/YahyaToubali/Crashwise/tree/main/packages/create-docusaurus/templates/shared/",
        },
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: [
    "@docusaurus/theme-mermaid",
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
      {
        // `hashed` is recommended as long-term-cache of index file is possible.
        hashed: true,

        language: ["en"],
      },
    ],
  ],

  themeConfig: {
    metadata: [
      {
        name: "keywords",
        content:
          "documentation, crashwise, crashwise, fuzzing, security, ai, ai-powered, vulnerability, analysis, platform",
      },
      { name: "twitter:card", content: "summary_large_image" },
    ],
    image: "img/crashwise-social-card.jpg",
    navbar: {
      title: "Crashwise Docs",
      logo: {
        alt: "Crashwise Logo",
        src: "img/crashwise-logo-1024-rounded.png",
      },
      items: [
        {
          type: "docSidebar",
          sidebarId: "backendSidebar",
          position: "left",
          label: "Workflow",
        },
        {
          type: "docSidebar",
          sidebarId: "aiSidebar",
          position: "left",
          label: "AI",
        },
        {
          href: "https://github.com/YahyaToubali/Crashwise",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Workflow",
          items: [
            {
              label: "Tutorials",
              to: "/docs/category/tutorial",
            },
            {
              label: "Concepts",
              to: "/docs/category/concept",
            },
            {
              label: "How-to Guides",
              to: "/docs/category/how-to-guides",
            },
            {
              label: "References",
              to: "/docs/category/reference",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "Website",
              href: "https://crashwise.ai/",
            },
            {
              label: "Discord",
              href: "https://discord.gg/jKBygqFkwn",
            },
            {
              label: "X",
              href: "https://x.com/YahyaToubali",
            },
            {
              label: "LinkedIn",
              href: "https://www.linkedin.com/company/crashwise",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "Crashwise Blog",
              to: "https://crashwise.com/security-blog/",
            },
            {
              label: "GitHub",
              href: "https://github.com/YahyaToubali/Crashwise",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Crashwise`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
