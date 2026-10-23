# rpmdb test fixtures

The `*.sqlite` files were generated with `python3 -I gen_fixtures.py` (CPython 3.13, SQLite 3.46.1):
rpm-style `Packages` tables (page size 512, rpm header blobs built in the script; one 5 KiB blob
spills into overflow pages, `packages-deep.sqlite` has 300 rows over a three-level B-tree, and
`packages-utf16le.sqlite` is the small database with `PRAGMA encoding = 'UTF-16le'`).
The ndb and Berkeley DB files are built by Go test helpers (`ndb_test.go`, `bdb_test.go`).

`real/` is git-ignored and may hold real databases for `real_test.go`, e.g.
`real/amazonlinux-2023-rpmdb.sqlite` extracted with
`crane export --platform linux/amd64 amazonlinux:2023 - | tar -x var/lib/rpm/rpmdb.sqlite`.
