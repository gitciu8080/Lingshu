---
name: docs-discovery
description: When fetching framework documentation and direct URL guesses return 404, use /llms.txt or /sitemap.xml to discover the real documentation index, then parallel-fetch discovered pages.
source: auto-skill
extracted_at: '2026-07-17T09:37:22.368Z'
---

# Documentation Discovery via llms.txt / sitemap.xml

## Problem

When trying to understand a new framework from its documentation site, guessing URLs based on common conventions (e.g. `/get_started/installation`, `/tutorial/agent`) often returns 404. Domains use non-obvious URL structures or versioned paths.

## Approach

1. **Fetch the machine-readable index first.** Many documentation sites expose:
   - `https://<domain>/llms.txt` — a plaintext index of every doc page URL + title, designed for LLM consumption
   - `https://<domain>/sitemap.xml` — standard XML sitemap
   - `https://<domain>/sitemap-0.xml` — paginated sitemaps

   `llms.txt` is preferred because it contains human-readable titles alongside URLs.

2. **Extract all URLs and their topics.** Parse the index to build a map of topics → URLs. Identify the URL pattern (e.g. `/versions/2.0.5dev/en/building-blocks/<topic>.md`).

3. **Prioritize pages to fetch.** Categorize by importance:
   - Quickstart / Getting Started
   - Core building blocks (Agent, Tool, Model)
   - Advanced features (Middleware, Permission, Plan)
   - Deployment / Operations

4. **Fetch in parallel.** Use multiple parallel `web_fetch` calls for the highest-priority pages. This maximizes throughput and builds an accurate mental model faster than sequential reads.

5. **Synthesize from parallel results.** Once core pages are fetched, the mental model is usually sufficient to write documentation or tutorials. Only fetch remaining pages if gaps remain.

## Why

Guessing URLs wastes turns on 404 errors. The `llms.txt` index is designed exactly for this use case — it's a complete, machine-readable table of contents that eliminates guesswork and enables efficient parallel fetching.

## How to apply

```text
Step 1: <web_fetch url="https://docs.<framework>.io/llms.txt" prompt="Extract all URLs and titles">
Step 2: Identify URL pattern and key topics
Step 3: <web_fetch> the quickstart + 3-4 core building-block pages in parallel
Step 4: Synthesize; fetch remaining pages only if gaps remain
```
