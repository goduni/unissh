// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  // Served from the custom domain unissh.dev at the ROOT. GitHub Pages
  // 301-redirects goduni.github.io/unissh/ -> unissh.dev/, so the site lives
  // at the domain root, not under /unissh/. base MUST match that root or every
  // /unissh/_astro/* asset 404s on the live domain (which is exactly what
  // happened while this said base: '/unissh/'). public/CNAME pins the domain
  // so an Actions deploy can't drop it.
  site: 'https://unissh.dev',
  base: '/',
  integrations: [
    starlight({
      title: 'UniSSH',
      description:
        'Open-source, self-hosted, zero-knowledge SSH client with end-to-end encrypted secret vaults, fleet operations, real terminals, SFTP and tunnels.',
      // Dark-first to match the product aesthetic.
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
      },
      // Product design tokens + Starlight brand overrides.
      customCss: ['./src/styles/theme.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/goduni/unissh',
        },
      ],
      // The custom landing page (src/pages/index.astro) owns '/'.
      // Docs live under their group slugs (overview/, architecture/, ...).
      sidebar: [
        {
          label: 'Overview',
          items: [
            { label: 'What is UniSSH', slug: 'overview/introduction' },
            { label: 'Install & prerequisites', slug: 'overview/install' },
            { label: 'Quickstart (local, no server)', slug: 'overview/quickstart' },
          ],
        },
        {
          label: 'Architecture',
          items: [
            { label: 'System overview', slug: 'architecture/system-overview' },
            {
              label: 'Security & zero-knowledge model',
              slug: 'architecture/zero-knowledge-model',
            },
            { label: 'Crypto & key hierarchy', slug: 'architecture/crypto-and-keys' },
            { label: 'Sync & anti-rollback model', slug: 'architecture/sync-model' },
          ],
        },
        {
          label: 'Components',
          items: [
            { label: 'rust-core: the universal core', slug: 'components/rust-core' },
            { label: 'Crate reference', slug: 'components/crates' },
            { label: 'Server & API surface', slug: 'components/server' },
            { label: 'Audit log & entry format', slug: 'components/server-audit' },
            { label: 'Desktop & mobile client', slug: 'components/client' },
            { label: 'Admin panel (server-ui)', slug: 'components/server-ui' },
          ],
        },
        {
          label: 'Operations',
          items: [
            { label: 'Build from source', slug: 'operations/build' },
            { label: 'Server configuration', slug: 'operations/configuration' },
            { label: 'Docker Compose deployment', slug: 'operations/deploy' },
            { label: 'CI/CD & releases', slug: 'operations/ci-cd' },
            { label: 'Backups & anti-rollback restore', slug: 'operations/backups' },
          ],
        },
      ],
    }),
  ],
});
