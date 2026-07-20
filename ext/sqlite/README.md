# Vendored SQLite

NTIP vendors the official SQLite **3.53.3** amalgamation published on
2026-06-26. The upstream archive is:

`https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip`

The amalgamation is in the public domain. See SQLite's copyright page:
`https://www.sqlite.org/copyright.html`.

Only `sqlite3.c`, `sqlite3.h`, and `sqlite3ext.h` are retained from upstream.
Verify them with `openssl dgst -sha3-256` against `SHA3SUMS` before changing
the pin. `ntip_sqlite.c` and `ntip_sqlite.h` are the small NTIP-owned binding
shim documented in their source.

The NTIP build must compile `sqlite3.c` and `ntip_sqlite.c` with libc and these
definitions:

- `SQLITE_THREADSAFE=1`
- `SQLITE_DQS=0`
- `SQLITE_DEFAULT_MEMSTATUS=0`
- `SQLITE_DEFAULT_WAL_SYNCHRONOUS=2`
- `SQLITE_OMIT_DEPRECATED`
- `SQLITE_OMIT_LOAD_EXTENSION`
- `SQLITE_USE_URI=0`

Runtime hardening and durability pragmas are applied by
`src/state/sqlite.zig`; compile-time definitions are not a substitute for
those connection checks.
