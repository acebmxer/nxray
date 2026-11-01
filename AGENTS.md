# AGENTS.md

Instructions for AI coding agents working in this repository. People
contributing by hand will find the same rules, in full, in
[CONTRIBUTING.md](CONTRIBUTING.md).

## Work from `dev`, not `main`

`dev` is where all work happens. `main` only moves when a release is merged,
so it is often days or weeks behind `dev`.

- Base your work on the latest `origin/dev`, even if your environment checked
  out `main` or the default branch for you:

  ```bash
  git fetch origin
  git switch -c <your-branch> origin/dev
  ```

- Confirm before you start: `git merge-base --is-ancestor origin/dev HEAD`
  must succeed.
- Pull requests target `dev`.

## Check that the work is not already done

Before starting a roadmap stage or a feature, look at `dev`, not `main`:

- the **Roadmap** in `README.md` (each stage is marked *built* or *planned*),
- `## [Unreleased]` in `CHANGELOG.md`,
- `git log origin/dev`.

A stage marked *built* on `dev` is done, even when `main` still says
*planned*. Pick the next stage that is *planned* on `dev`.

## Rules

- **Read [`docs/functions.md`](docs/functions.md) before writing a function.**
  If one already does the job, call it. Add, rename or remove a row in the
  same change as the function; `tests/test_function_index.py` fails the build
  otherwise.
- **Every user-facing change gets a `CHANGELOG.md` entry** under
  `## [Unreleased]`, in the right subsection, newest first. Repository
  plumbing (CI, templates, editor settings) gets none.
- **Documentation under `docs/` ships with the code**, not after it.
- **One place for each setting.** Only `app/config.py` reads `os.environ`;
  every setting is described in `nxray.env.example` and
  `docs/configuration.md`.
- **Migrations are append-only**: add to the end of `_MIGRATIONS` in
  `app/db.py`, never edit an applied one.
- **Nothing changes the switch by accident.** Only `show` commands go through
  `NxapiClient.show()`. Each configuration change gets its own method that
  builds its one command from checked values; never add a way to send free
  text. Every form that changes something calls `require_csrf` first.
- **Never commit real switch output unscrubbed.** Replace serial numbers,
  hostnames, addresses, usernames and port descriptions in fixtures.
- Tests never need a real switch: the NX-API client is tested against a mock
  transport, and parsers against recorded output in `tests/fixtures/`.

## Checks

The same checks CI runs:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m pytest
docker build -t nxray:dev .
```

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `test:`, `refactor:`, `chore:`, a short one-line summary, and at most
a short body.
