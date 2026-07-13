# Comparison wiki

Astro + Starlight site serving the authorization-paradigm comparison wiki. The content is **not**
in this project — it lives in the repo's [`docs/wiki/`](../../docs/wiki/) so it stays readable on
GitHub; `src/content.config.ts` points the docs collection there. The overview matrix page
(`paradigm-comparison.md`, frontmatter `slug: index`) is the site index.

Mermaid code blocks are rendered to SVG at build time via `rehype-mermaid`, which needs a
Playwright Chromium once per machine:

```
npx playwright install chromium
```

Dev server only for now — no hosting target, no deploy pipeline, no CI
([#16](https://github.com/Schinkenkoenig/authn-authz-prototype/issues/16)).

```
npm install
npm run dev        # http://localhost:4321 — Astro daemonizes; stop with `npx astro dev stop`
npm run build      # static build to ./dist/
```
