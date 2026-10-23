#!/usr/bin/env python3
"""Generate the SQLite fixtures used by the rpmdb tests.

Run from this directory with: python3 -I gen_fixtures.py

Every fixture is an rpm-style database: a table
'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)
whose blobs are rpm header blobs exactly as rpm stores them (index length,
data length, index entries and data; no leading header magic). The page size
is 512 so that a handful of rows already produces interior B-tree pages and a
5000-byte blob spills into overflow pages. The expected contents are listed
in sqlite_test.go.
"""
import os
import sqlite3
import struct

TAG_NAME, TAG_VERSION, TAG_RELEASE, TAG_EPOCH, TAG_SUMMARY, TAG_GIF, TAG_ARCH = 1000, 1001, 1002, 1003, 1004, 1013, 1022
T_INT32, T_BIN, T_STRING, T_I18N = 4, 7, 6, 9


def header(entries, region=False):
    """Build an rpm header blob from (tag, type, bytes, count, align) tuples."""
    index, data = b"", b""
    for tag, typ, payload, count, align in entries:
        if len(data) % align:
            data += b"\0" * (align - len(data) % align)
        index += struct.pack(">iIiI", tag, typ, len(data), count)
        data += payload
    if region:
        # Region tag 63 as rpm writes it: a 16-byte trailer at the end of the
        # data whose offset field points back at the start of the index.
        il = len(entries) + 1
        trailer = struct.pack(">iIiI", 63, T_BIN, -(il * 16), 16)
        index = struct.pack(">iIiI", 63, T_BIN, len(data), 16) + index
        data += trailer
    il = len(index) // 16
    return struct.pack(">II", il, len(data)) + index + data


def s(tag, text):
    return (tag, T_STRING, text.encode() + b"\0", 1, 1)


def i18n(tag, text):
    return (tag, T_I18N, text.encode() + b"\0", 1, 1)


def i32(tag, value):
    return (tag, T_INT32, struct.pack(">i", value), 1, 4)


def binary(tag, blob):
    return (tag, T_BIN, blob, len(blob), 1)


def nevra(name, version, release, arch, epoch=None, extra=(), region=False):
    entries = [s(TAG_NAME, name), s(TAG_VERSION, version), s(TAG_RELEASE, release)]
    if epoch is not None:
        entries.append(i32(TAG_EPOCH, epoch))
    entries.extend(extra)
    if arch is not None:
        entries.append(s(TAG_ARCH, arch))
    return header(entries, region)


SMALL = [
    nevra("ca-certificates", "2025.2.80_v9.0.305", "91.el9", "noarch", extra=[i18n(TAG_SUMMARY, "The Mozilla CA root certificate bundle")], region=True),
    nevra("openssl-libs", "3.5.8", "2.el9_8", "x86_64", epoch=1),
    nevra("p11-kit", "0.26.4", "1.el9_8", "x86_64", epoch=0),
    nevra("gpg-pubkey", "fd431d51", "4ae0493b", None),
    nevra("big-package", "7.0", "1", "noarch", extra=[binary(TAG_GIF, bytes(range(256)) * 20)]),  # 5120-byte blob -> overflow pages
    nevra("zlib", "1.2.13", "4.el9", "x86_64"),
]


def write(path, rows, encoding="UTF-8", table="Packages"):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size = 512")
    con.execute("PRAGMA encoding = '%s'" % encoding)
    con.execute("PRAGMA journal_mode = DELETE")
    con.execute("CREATE TABLE 'Name' (key 'TEXT' NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL)")
    con.execute("CREATE TABLE '%s' (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)" % table)
    con.executemany("INSERT INTO '%s' (blob) VALUES (?)" % table, [(sqlite3.Binary(r),) for r in rows])
    con.execute("INSERT INTO 'Name' VALUES ('zlib', 6, 0)")
    con.commit()
    con.close()


here = os.path.dirname(os.path.abspath(__file__))
write(os.path.join(here, "packages-small.sqlite"), SMALL)
write(os.path.join(here, "packages-utf16le.sqlite"), SMALL, encoding="UTF-16le")
write(os.path.join(here, "packages-deep.sqlite"), [nevra("pkg%03d" % i, "1.%d" % i, "r%d" % (i % 7), "noarch") for i in range(300)])
write(os.path.join(here, "no-packages-table.sqlite"), [], table="Other")
