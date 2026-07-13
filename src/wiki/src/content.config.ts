import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// The wiki content lives in the repo's docs/ tree (docs/wiki/), not in this
// project — the markdown stays readable on GitHub and is consumed here, not forked.
export const collections = {
	docs: defineCollection({
		loader: glob({ base: '../../docs/wiki', pattern: '**/[^_]*.md' }),
		schema: docsSchema(),
	}),
};
