#include "yarrp.h"
#include <cassert>


// Function to determine if an IPv6 address is a global unicast address under 2000::/4
bool isGlobalUnicast(const struct in6_addr* node) {
    // We need to check the first byte of the address to determine if it is 0010xxxx
    // The first byte is node->s6_addr[0]
    // 0x20 in hexadecimal corresponds to 0010 0000 in binary
    return (node->s6_addr[0] & 0xF0) == 0x20;
}


void NodeDatabase::open(const char *sqlite_path) {
    assert(sqlite_path);
    int rc = sqlite3_open(sqlite_path, &db);
    if (rc) {
        std::cerr << "can't open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    } else {
        const char* createTableSQL = "CREATE TABLE IF NOT EXISTS Node ("
                                    "node_addr BINARY(16) NOT NULL,"
                                    "timestamp INTEGER NOT NULL,"
                                    "PRIMARY KEY (node_addr));";
        char* errMsg = 0;
        rc = sqlite3_exec(db, createTableSQL, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } 
        return;
    }
}


bool NodeDatabase::exist(const struct in6_addr* node, uint32_t currentTime) {
    if (!isGlobalUnicast(node)) {
        return false;
    }
    sqlite3_stmt* stmt;
    const char* sql = "SELECT EXISTS(SELECT 1 FROM Node WHERE node_addr = ? AND (? - timestamp <= ?))";
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    rc = sqlite3_bind_blob(stmt, 1, node->s6_addr, sizeof(node->s6_addr), SQLITE_STATIC);
    rc = rc == SQLITE_OK ? sqlite3_bind_int(stmt, 2, currentTime) : rc;
    rc = rc == SQLITE_OK ? sqlite3_bind_int(stmt, 3, validSecs) : rc;

    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }

    sqlite3_finalize(stmt);
    return exists;
}


bool NodeDatabase::insert(const struct in6_addr* node, uint32_t currentTime) {
    if (!isGlobalUnicast(node)) {
        return false;
    }
    sqlite3_stmt* stmt;
    const char* sqlInsert = "INSERT INTO Node (node_addr, timestamp) VALUES (?, ?) ON CONFLICT(node_addr) DO UPDATE SET timestamp = excluded.timestamp";
    int rc = sqlite3_prepare_v2(db, sqlInsert, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    rc = sqlite3_bind_blob(stmt, 1, node->s6_addr, sizeof(node->s6_addr), SQLITE_STATIC);
    rc = rc == SQLITE_OK ? sqlite3_bind_int(stmt, 2, currentTime) : rc;

    if (rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return false;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE || rc == SQLITE_OK;
}