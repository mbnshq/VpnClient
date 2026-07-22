# Database - SQLite catalogue: the contract, the migration set and the
# SQLite-backed implementation.

nova_add_module(Database
    SOURCES
        src/Schema.cpp
        src/SqliteDatabase.cpp
    HEADERS
        include/NovaVPN/Database/Database.h
    DEPENDS
        nova::core
        nova::logs
    PRIVATE_DEPENDS
        nova::sqlite)
