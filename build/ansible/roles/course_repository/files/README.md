# Sanitized teaching repository

`hedgehog-config-sanitized.bundle` is devb's complete sanitized 11-commit history
of production's `student/hedgehog-config`, supplied by the owner on 2026-11-11.
Its SHA256 is `e5e735e2619ec0f393f0936095e8b7685a264e5d4e8cf2ed6aaf3989451579c2`.
The source evidence manifest has SHA256
`85331ff68002665417e070c3907c3b41cc25ebb8c022d7b82a553dcc3dd00d41`.
`commit-map.tsv` preserves the original-to-sanitized mapping and metadata;
its SHA256 is `7d4b3df0cd755cca7b04ab18de20e2d105e989ac533a76e1a72a8830d2d88f07`.

devb removed credential values from every affected revision of README.md and
active/lab-info.yaml, replacing them with `<redacted>`. The first commit is
unchanged; commits 2–11 have new hashes. Authors, committers, dates, messages
and educational changes are preserved. The release selects the exact sanitized
tip. No restricted production archive or shell configuration is included.

Clone or fetch from this bundle; do not replay patches with `git am`, which
would rewrite committer metadata. The role creates a bare build seed at
`/opt/labapp/seed/hedgehog-config.git`; subsequent Gitea bootstrap must publish
its main branch without recreating commits. This role does not create a Gitea
service/repository or push to it.

This is an immutable build seed. Reapplying the same release preserves it; an
existing seed at a different revision fails the final assertion. Use a fresh
builder for a release with different teaching history.

Redactions remain in the teaching history. Retrieve build-specific credentials
through the normal service bootstrap; do not restore captured passwords or
commit replacement secrets. The course's public Grafana admin/admin login is
selected separately in the release's service configuration.
