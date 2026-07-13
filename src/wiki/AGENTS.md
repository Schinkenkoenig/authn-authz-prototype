# wiki

The paradigm-comparison wiki site. **Content lives in the repo's `docs/wiki/`, not here** — the
docs collection in `src/content.config.ts` globs `../../docs/wiki`; edit the markdown there, never
fork it into `src/content/`. Starlight needs frontmatter (`title`, optional `slug`) on those files.
`rehype-mermaid` renders mermaid blocks to SVG at build time and needs a one-time
`npx playwright install chromium`. Deployed to GitHub Pages
(https://schinkenkoenig.github.io/authn-authz-prototype/) by `.github/workflows/deploy-wiki.yml` on
push to `main`; test CI (Playwright, issue #11) stays deferred. Because of the Pages `base` path,
links in the wiki markdown to repo files outside `docs/wiki/` must be absolute GitHub blob URLs —
relative `../` links 404 on the published site.

## Development

When starting the dev server, use background mode:

```
astro dev --background
```

Manage the background server with `astro dev stop`, `astro dev status`, and `astro dev logs`.

## Documentation

Full documentation: https://docs.astro.build

Consult these guides before working on related tasks:

- [Adding pages, dynamic routes, or middleware](https://docs.astro.build/en/guides/routing/)
- [Working with Astro components](https://docs.astro.build/en/basics/astro-components/)
- [Using React, Vue, Svelte, or other framework components](https://docs.astro.build/en/guides/framework-components/)
- [Adding or managing content](https://docs.astro.build/en/guides/content-collections/)
- [Adding styles or using Tailwind](https://docs.astro.build/en/guides/styling/)
- [Supporting multiple languages](https://docs.astro.build/en/guides/internationalization/)
