# Single source of truth for the product version.
#
# NOVAVPN_VERSION           - dotted numeric version consumed by project()
# NOVAVPN_VERSION_CHANNEL   - dev | beta | stable, surfaced in the updater feed
# NOVAVPN_VERSION_BUILD     - CI build number (0 for local builds)

set(NOVAVPN_VERSION       "0.1.0")
set(NOVAVPN_VERSION_CHANNEL "dev" CACHE STRING "Release channel (dev|beta|stable)")
set_property(CACHE NOVAVPN_VERSION_CHANNEL PROPERTY STRINGS dev beta stable)

if(DEFINED ENV{NOVAVPN_BUILD_NUMBER})
    set(NOVAVPN_VERSION_BUILD "$ENV{NOVAVPN_BUILD_NUMBER}")
else()
    set(NOVAVPN_VERSION_BUILD "0")
endif()
