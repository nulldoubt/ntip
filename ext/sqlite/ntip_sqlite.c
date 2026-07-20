#include "ntip_sqlite.h"

int ntip_sqlite_bind_text_transient(
    sqlite3_stmt *statement,
    int index,
    const char *value,
    sqlite3_uint64 length
) {
    return sqlite3_bind_text64(
        statement,
        index,
        value,
        length,
        SQLITE_TRANSIENT,
        SQLITE_UTF8
    );
}

int ntip_sqlite_bind_blob_transient(
    sqlite3_stmt *statement,
    int index,
    const void *value,
    sqlite3_uint64 length
) {
    return sqlite3_bind_blob64(statement, index, value, length, SQLITE_TRANSIENT);
}
