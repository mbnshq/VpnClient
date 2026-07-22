// NovaVPN - Services/ServiceApi.h
// Wires the IPC method handlers to the service subsystems.
//
// This is the boundary where a remote request becomes a call into the profile
// store, the tunnel manager, the firewall and the engine registry. Keeping it
// in one place means the mapping from Method to behaviour is auditable, and the
// handlers can be registered against a real IPC server in a test without
// standing up the whole Windows service.
#pragma once

#include <NovaVPN/Core/EventBus.h>
#include <NovaVPN/Core/Result.h>
#include <NovaVPN/Profiles/ProfileStore.h>
#include <NovaVPN/Services/IpcServer.h>
#include <NovaVPN/Tunnel/Tunnel.h>

#include <memory>

namespace nova::service {

/// Subsystems the API handlers dispatch to. Any may be null; a handler whose
/// subsystem is absent returns Unavailable rather than faulting.
struct ServiceApiDeps {
    profiles::ProfileStorePtr    profiles;
    tunnel::TunnelManagerPtr     tunnels;
    tunnel::EngineRegistryPtr    engines;
    profiles::CredentialStorePtr credentials;
    std::shared_ptr<EventBus>    events;
};

/// Registers every implemented IPC handler on `server`. Also subscribes to the
/// event bus so tunnel state changes and statistics ticks are broadcast to
/// connected clients. The returned subscriptions must outlive the server.
[[nodiscard]] Result<std::vector<EventBus::Subscription>> registerServiceApi(
    ipc::IIpcServer& server, ServiceApiDeps deps);

} // namespace nova::service
