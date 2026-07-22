# Driver - Wintun adapter ownership and the split-tunnel callout driver's
# user-mode control surface. Contract only in Phase 1; implemented in Phase 3
# (Wintun) and Phase 4 (callout).

nova_add_module(Driver
    HEADERS
        include/NovaVPN/Driver/WintunAdapter.h
    DEPENDS
        nova::core
        nova::networking)
