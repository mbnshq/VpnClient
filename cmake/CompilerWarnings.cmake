# Warning/hardening flags applied to every first-party target through the
# nova::warnings and nova::hardening interface libraries.

add_library(nova_warnings INTERFACE)
add_library(nova::warnings ALIAS nova_warnings)

add_library(nova_hardening INTERFACE)
add_library(nova::hardening ALIAS nova_hardening)

if(MSVC)
    target_compile_options(nova_warnings INTERFACE
        /W4                 # high warning level
        /permissive-        # strict conformance
        /w14242 /w14254 /w14263 /w14265 /w14287
        /w14296 /w14311 /w14545 /w14546 /w14547
        /w14549 /w14555 /w14619 /w14640 /w14826
        /w14905 /w14906 /w14928
        /wd4324             # structure padded due to alignas - intentional
        /Zc:__cplusplus     # report the real __cplusplus value
        /Zc:preprocessor    # conforming preprocessor
        /Zc:inline
        /MP                 # parallel compilation
        /utf-8)

    if(NOVAVPN_WARNINGS_AS_ERRORS)
        target_compile_options(nova_warnings INTERFACE /WX)
    endif()

    # Exploit mitigations expected of a signed, service-hosted product.
    target_compile_options(nova_hardening INTERFACE
        /GS                 # buffer security checks
        /guard:cf           # control flow guard
        /Qspectre           # speculative-execution mitigations
        $<$<CONFIG:Release,RelWithDebInfo>:/Gy>
        $<$<CONFIG:Release,RelWithDebInfo>:/Zi>)

    target_link_options(nova_hardening INTERFACE
        /GUARD:CF
        /DYNAMICBASE
        /NXCOMPAT
        /HIGHENTROPYVA
        $<$<CONFIG:Release,RelWithDebInfo>:/DEBUG>
        $<$<CONFIG:Release,RelWithDebInfo>:/OPT:REF>
        $<$<CONFIG:Release,RelWithDebInfo>:/OPT:ICF>)
endif()

target_compile_definitions(nova_hardening INTERFACE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    STRICT
    _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=${NOVAVPN_WIN32_WINNT}
    WINVER=${NOVAVPN_WIN32_WINNT}
    NTDDI_VERSION=0x0A000000)

if(NOVAVPN_ENABLE_ASAN AND MSVC)
    target_compile_options(nova_hardening INTERFACE /fsanitize=address)
    # ASan is incompatible with incremental linking and edit-and-continue.
    target_compile_options(nova_hardening INTERFACE $<$<CONFIG:Debug>:/Zi>)
    target_link_options(nova_hardening INTERFACE /INCREMENTAL:NO)
endif()
