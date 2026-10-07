# Releasing

Trace2API is not published to PyPI yet. A release is a tagged commit on `main`, a wheel
and an sdist built from it, and a changelog entry, nothing more.

## Versioning

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html):
`MAJOR.MINOR.PATCH`. Before `1.0.0`:

- A `MINOR` bump marks a release with new commands, new generator targets, or other
  functionality landing.
- A `PATCH` bump marks a release limited to fixes, documentation, or packaging changes.
- Breaking changes to a command's output format or a generated client's shape are called
  out in the changelog entry even though semver does not require a `MAJOR` bump before
  `1.0.0`.

## Checklist

1. Confirm `main` is healthy: CI green on the latest commit, no open pull request left
   unmerged from the milestone being released.
2. Decide the new version number from the changes since the last release, following the
   rule above.
3. Update `version` in `pyproject.toml` and `__version__` in `src/trace2api/__init__.py`
   to match.
4. Add a dated entry at the top of `CHANGELOG.md` under a new `## [VERSION] - DATE`
   heading, grouping changes as `Added`, `Changed`, `Fixed`, or `Removed`. Draw it from the
   Ticket Board and Recent Progress in `README.md`, not from commit messages, since a
   changelog entry describes what changed for a user of the package rather than how the
   work was done.
5. Run the full local check sequence and confirm it passes:

   ```console
   $ ruff format --check .
   $ ruff check .
   $ pytest
   $ python -m build
   ```

6. Open a pull request with only the version bump and the changelog entry, titled for the
   release, for example `release: v0.1.0`.
7. Once that pull request is merged, tag the resulting commit on `main`:

   ```console
   $ git tag -a v0.1.0 -m "v0.1.0"
   $ git push origin v0.1.0
   ```

8. Build the wheel and sdist from the tagged commit and confirm `trace2api --help` and
   `trace2api version` work from each:

   ```console
   $ python -m build
   $ python -m pip install dist/trace2api-0.1.0-py3-none-any.whl
   $ trace2api version
   ```

9. Publishing to PyPI is out of scope until the project is ready for it. Until then, a
   release is the tag plus the built artifacts, and the installation methods in the
   README (`pipx`, `uvx`, cloning the repository) keep working against the tagged commit.

## Release notes

The changelog entry added in step 4 is the release notes. A GitHub release, once the
project publishes one, copies that entry rather than restating it differently.
