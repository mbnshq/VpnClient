# Database - SQLite catalogue contract and the migration set.
# The SQLite implementation lands in Phase 3.

nova_add_module(Database
    SOURCES
        src/Schema.cpp
    HEADERS
        include/NovaVPN/Database/Database.h
    DEPENDS
        nova::core
        nova::logs)
