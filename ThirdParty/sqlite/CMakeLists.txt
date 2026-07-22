# SQLite amalgamation, vendored (upstream ships an amalgamation, not a package).
# Version 3.46.1. See ../README.md for the acquisition policy.
#
# Compile-time configuration is deliberate rather than default: the features
# NovaVPN does not use are switched off to shrink the binary and the attack
# surface, and the ones it relies on (WAL, foreign keys) are switched on.

add_library(novavpn_sqlite STATIC
    sqlite3.c
    sqlite3.h)

add_library(nova::sqlite ALIAS novavpn_sqlite)

target_include_directories(novavpn_sqlite PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

# CAUTION: SQLite tests the OMIT_*/ENABLE_* switches with #ifdef, so defining
# one to 0 has the same effect as defining it to 1. Only the numeric-valued
# switches (DQS, THREADSAFE, TEMP_STORE, ...) may be set to a value; the feature
# toggles must be either present-to-omit or absent-to-keep. In particular
# SQLITE_OMIT_AUTOINIT must NOT appear here, or sqlite3_initialize never runs
# and the first sqlite3_open_v2 faults.
target_compile_definitions(novavpn_sqlite PRIVATE
    SQLITE_DQS=0                 # reject double-quoted string literals (a footgun)
    SQLITE_THREADSAFE=1          # serialized: the UI reads while the service writes
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
    SQLITE_MAX_EXPR_DEPTH=100
    SQLITE_USE_URI=1
    SQLITE_TEMP_STORE=2          # keep temp b-trees in memory, never on disk
    SQLITE_LIKE_DOESNT_MATCH_BLOBS  # present-to-enable
    SQLITE_OMIT_DEPRECATED          # present-to-omit
    SQLITE_OMIT_SHARED_CACHE)       # one connection per process role

# Third-party C: silence its warnings so the strict first-party flags do not
# fail the build on code we do not own, but keep it out of the /WX net entirely.
if(MSVC)
    target_compile_options(novavpn_sqlite PRIVATE /w)
endif()

set_target_properties(novavpn_sqlite PROPERTIES FOLDER "ThirdParty")
