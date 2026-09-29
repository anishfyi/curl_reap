# Changelog

Full history, including releases before 1.0.0: https://velofy.co/curl_reap/changelog/

## 1.1.0 (2026-09-30)

### Fixed

- The `reap` command line tool works again. In 1.0.0 it failed at startup with a `SyntaxError` in `curl_reap/cli.py`, where two statements shared one line.

### Added

- Optional HTTP/2 transport through hyper-h2: `Session(http2=True)`, `reap --http2`, and a new `h2` extra. Falls back to HTTP/1.1 when the server or the environment does not support it. Response bodies over HTTP/2 are not content-decoded yet.
- `impersonate=` as an alias of `profile=`, with 38 versioned Chrome, Edge, Firefox and Safari targets plus four aliases in `reap.FINGERPRINTS`, and a CLI `--impersonate` option.
- `Session.cookies`, a `CookieJar` that stores cookies from responses and redirect hops and replays them. Exported as `reap.CookieJar`.
- Streaming downloads: `Session.download()`, `reap.download()` and `AsyncSession.download()`.
- `Response.looks_like_challenge`.
- `reap.render()` and `reap.render_if_empty()` through Playwright, in a new `js` extra.
- `reap.TransportError` exported at the package root.

### Tests and CI

- CLI tests: import, `--help`, and `reap get` against a local server.
- CI runs `reap --help` on every Python version.
- The CI check that `curl_cffi` is gone from the package can now fail. Before, a negated `grep` in a bash step could never fail the job.
- An adversarial transport test suite, and a CI matrix for Python 3.9 to 3.13.

### Other

- The Geocoder's default User-Agent now says `curl_reap/1.1`.
- Documentation moved to https://velofy.co/curl_reap/.

## 1.0.0 (2026-08-22)

The from-scratch, breaking release: curl_cffi removed, a standard-library HTTP/1.1 transport with browser TLS and header profiles, and `profile=` in place of `impersonate=`. GitHub release only; it was not uploaded to PyPI.
