# Contributing

## Ground rule: check the function index first

Before writing a new function, read [`docs/functions.md`](docs/functions.md).
If something there already does the job, call it. A second implementation of
an existing thing creates the bug that fires the next time someone fixes only
one copy.

If a second implementation is genuinely necessary, say so in its row and in a
comment on the function itself:

```python
# Deliberately not `existing_thing`, because <reason>. Do not add a third.
```

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Run it locally without Docker:

```bash
export NXRAY_DATA_DIR=./data
export NXRAY_ADMIN_PASSWORD_HASH="$(echo 'devpassword' | .venv/bin/python -m app.hashpw | grep -oP '(?<=HASH=).*')"
.venv/bin/uvicorn app.main:app --reload --port 8080
```

Tests never need a switch: the NX-API client is tested against a mock
transport, and the parsers against output recorded from a real switch in
`tests/fixtures/`.

## Before opening a pull request

The same checks CI runs:

```bash
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m pytest
docker build -t nxray:dev .
```

## Conventions

**Pull requests target `dev`.** `main` only moves when a release is merged.

**Update the function index in the same commit.** A commit that adds,
renames, changes the signature of, or removes a public function and does not
touch `docs/functions.md` is incomplete. `tests/test_function_index.py` fails
the build when a function has no row, or a row names a function that is gone.

**Update the CHANGELOG in the same pass.** Every user-facing change gets an
entry under `## [Unreleased]`, in the right subsection, newest first.
Repository plumbing (CI config, issue templates, editor settings) gets no
entry.

**Documentation ships with the code**, not after it.

**One place for each setting.** `app/config.py` is the only module that reads
`os.environ`, and every setting it reads is described in `nxray.env.example`
and `docs/configuration.md`.

**Migrations are append-only.** Add to the end of `_MIGRATIONS` in
`app/db.py`. Editing an applied migration leaves existing databases behind.

**Nothing changes the switch by accident.** Only `show` commands go through
`NxapiClient.show()`. Configuration changes get their own, separately guarded
method when the first feature needs one.

**Never commit real switch output unscrubbed.** Replace serial numbers,
hostnames, addresses, usernames and port descriptions before adding a fixture.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
`docs:`, `test:`, `refactor:`, `chore:`.

## Branches and releases

Work happens on `dev` and reaches `main` through a pull request. The changelog
version section is part of the branch the pull request carries. The tag is
created on `main` after the merge.
