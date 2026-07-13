// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import rehypeMermaid from 'rehype-mermaid';

// https://astro.build/config
export default defineConfig({
	markdown: {
		// Mermaid code blocks are rendered to SVG at build time (no client-side JS).
		rehypePlugins: [rehypeMermaid],
	},
	integrations: [
		starlight({
			title: 'Authorization paradigm comparison',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/Schinkenkoenig/authn-authz-prototype',
				},
			],
		}),
	],
});
