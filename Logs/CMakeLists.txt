# Logs - structured, asynchronous logging used by every other module.

nova_add_module(Logs
    SOURCES
        src/LogRecord.cpp
        src/Logger.cpp
        src/Sink.cpp
    HEADERS
        include/NovaVPN/Logs/LogRecord.h
        include/NovaVPN/Logs/Logger.h
        include/NovaVPN/Logs/Sink.h
    DEPENDS
        nova::core
    SYSTEM
        advapi32)
