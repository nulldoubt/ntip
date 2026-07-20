#ifndef NTIP_SQLITE_H
#define NTIP_SQLITE_H

#include "sqlite3.h"

/*
 * Zig cannot materialize SQLite's intentionally invalid function-pointer
 * sentinel (`SQLITE_TRANSIENT`, address -1) on architectures with aligned
 * function pointers. Keep that C-only ABI detail behind two ordinary calls.
 */
int ntip_sqlite_bind_text_transient(
    sqlite3_stmt *statement,
    int index,
    const char *value,
    sqlite3_uint64 length
);

int ntip_sqlite_bind_blob_transient(
    sqlite3_stmt *statement,
    int index,
    const void *value,
    sqlite3_uint64 length
);

#endif
