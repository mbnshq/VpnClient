# nova_add_module() - declares one NovaVPN module with the project conventions
# baked in: public headers under <dir>/include, sources under <dir>/src, the
# nova::<name> alias, warning/hardening flags and IDE folder placement.
#
#   nova_add_module(Core
#       SOURCES  src/Status.cpp src/Logger.cpp
#       HEADERS  include/NovaVPN/Core/Status.h
#       DEPENDS  nova::logs
#       SYSTEM   ws2_32 iphlpapi)
#
# A module with no SOURCES becomes an INTERFACE library (contract-only module,
# implemented in a later phase).

function(nova_add_module NAME)
    cmake_parse_arguments(ARG "" "FOLDER" "SOURCES;HEADERS;DEPENDS;PRIVATE_DEPENDS;SYSTEM;DEFINES" ${ARGN})

    string(TOLOWER "${NAME}" _lower)
    set(_target "novavpn_${_lower}")

    if(ARG_SOURCES)
        add_library(${_target} STATIC ${ARG_SOURCES} ${ARG_HEADERS})
        set(_scope PUBLIC)
        set(_iface PUBLIC)
    else()
        add_library(${_target} INTERFACE)
        if(ARG_HEADERS)
            # Keep contract-only headers visible in the IDE.
            target_sources(${_target} INTERFACE FILE_SET nova_headers TYPE HEADERS
                BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
                FILES ${ARG_HEADERS})
        endif()
        set(_scope INTERFACE)
        set(_iface INTERFACE)
    endif()

    add_library(nova::${_lower} ALIAS ${_target})

    target_include_directories(${_target} ${_iface}
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

    if(ARG_SOURCES)
        target_include_directories(${_target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    endif()

    if(ARG_DEFINES)
        target_compile_definitions(${_target} ${_iface} ${ARG_DEFINES})
    endif()

    target_link_libraries(${_target} ${_iface} nova::hardening ${ARG_DEPENDS} ${ARG_SYSTEM})

    if(ARG_SOURCES)
        target_link_libraries(${_target} PRIVATE nova::warnings ${ARG_PRIVATE_DEPENDS})
    endif()

    if(ARG_FOLDER)
        set_target_properties(${_target} PROPERTIES FOLDER "${ARG_FOLDER}")
    else()
        set_target_properties(${_target} PROPERTIES FOLDER "Modules")
    endif()
endfunction()

# nova_add_executable() - same conventions for the shipped binaries.
function(nova_add_executable NAME)
    cmake_parse_arguments(ARG "WIN32_GUI" "FOLDER;OUTPUT_NAME" "SOURCES;HEADERS;DEPENDS;SYSTEM;DEFINES" ${ARGN})

    if(ARG_WIN32_GUI)
        add_executable(${NAME} WIN32 ${ARG_SOURCES} ${ARG_HEADERS})
    else()
        add_executable(${NAME} ${ARG_SOURCES} ${ARG_HEADERS})
    endif()

    target_include_directories(${NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(${NAME} PRIVATE nova::warnings nova::hardening ${ARG_DEPENDS} ${ARG_SYSTEM})

    if(ARG_DEFINES)
        target_compile_definitions(${NAME} PRIVATE ${ARG_DEFINES})
    endif()
    if(ARG_OUTPUT_NAME)
        set_target_properties(${NAME} PROPERTIES OUTPUT_NAME "${ARG_OUTPUT_NAME}")
    endif()
    set_target_properties(${NAME} PROPERTIES FOLDER "${ARG_FOLDER}")
endfunction()
