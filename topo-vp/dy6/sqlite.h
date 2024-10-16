#ifndef SQLITE_H
#define SQLITE_H

#include <sqlite3.h>


class NodeDatabase {
    private:
    sqlite3* db;
    uint32_t validSecs;
    public:
    NodeDatabase(uint32_t validSecs) : db(NULL), validSecs(validSecs) {};
    ~NodeDatabase() {
        if (db) {
            sqlite3_close(db);
        }
    };
    void open(const char *sqlite_path);
    bool exist(const struct in6_addr* node, uint32_t currentTime);
    bool insert(const struct in6_addr* node, uint32_t currentTime);
};

#endif