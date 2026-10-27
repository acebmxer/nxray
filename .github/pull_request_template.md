## What this changes

<!-- One or two sentences. What does a user get, or what breaks less? -->

## Why

<!-- The problem behind the change. Link an issue if there is one. -->

## Checklist

Tick only what you actually did. An optimistic tick is a false claim about
the state of the repository; leave the rest unticked with a note saying why.

- [ ] This pull request targets `dev`, not `main`
- [ ] `docs/functions.md` was read before adding functions, and new, renamed
      or removed public functions have their rows updated
- [ ] `CHANGELOG.md` has an entry under `[Unreleased]` (skip for repository
      plumbing: CI config, templates, editor settings)
- [ ] Documentation under `docs/` updated alongside the code
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] `python -m pytest` passes
- [ ] `docker build .` succeeds

## Testing

<!-- What you actually ran, and what you did not. If a path was only reasoned
     about rather than exercised, say so here. -->
