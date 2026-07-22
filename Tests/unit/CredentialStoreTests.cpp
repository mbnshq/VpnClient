// These use the real Windows Credential Manager under a test-scoped target
// name, and clean up after themselves. They exercise the machine vault the
// same way the service will, so they need no elevation (per-user vault write
// is always permitted).
#include <NovaVPN/Core/Uuid.h>
#include <NovaVPN/Profiles/ProfileStore.h>

#include <catch2/catch_test_macros.hpp>

using namespace nova;
using namespace nova::profiles;

namespace {

/// A unique target per test run, deleted on scope exit so a crashed test never
/// leaves an entry behind in the developer's vault.
class ScopedTarget {
public:
    explicit ScopedTarget(CredentialStorePtr store)
        : m_store(std::move(store)), m_target("test/" + Uuid::generate().toString())
    {
    }
    ~ScopedTarget() { (void)m_store->erase(m_target); }

    [[nodiscard]] const std::string& name() const { return m_target; }

private:
    CredentialStorePtr m_store;
    std::string        m_target;
};

} // namespace

TEST_CASE("a stored secret round-trips through the vault", "[credentials]")
{
    auto store = makeCredentialStore();
    ScopedTarget target{store};

    REQUIRE_FALSE(store->contains(target.name()));

    REQUIRE(store->store(target.name(), "alice", SecureString{"hunter2"}).isOk());
    REQUIRE(store->contains(target.name()));

    auto secret = store->retrieve(target.name());
    REQUIRE(secret.isOk());
    REQUIRE(secret.value().equals("hunter2"));

    auto user = store->userNameFor(target.name());
    REQUIRE(user.isOk());
    REQUIRE(user.value() == "alice");
}

TEST_CASE("storing again overwrites the previous secret", "[credentials]")
{
    auto store = makeCredentialStore();
    ScopedTarget target{store};

    REQUIRE(store->store(target.name(), "alice", SecureString{"first"}).isOk());
    REQUIRE(store->store(target.name(), "alice", SecureString{"second"}).isOk());

    auto secret = store->retrieve(target.name());
    REQUIRE(secret.isOk());
    REQUIRE(secret.value().equals("second"));
}

TEST_CASE("erase removes the secret and is idempotent", "[credentials]")
{
    auto store = makeCredentialStore();
    ScopedTarget target{store};

    REQUIRE(store->store(target.name(), "", SecureString{"x"}).isOk());
    REQUIRE(store->contains(target.name()));

    REQUIRE(store->erase(target.name()).isOk());
    REQUIRE_FALSE(store->contains(target.name()));

    // Erasing an absent credential satisfies the postcondition already.
    REQUIRE(store->erase(target.name()).isOk());
}

TEST_CASE("retrieving a missing credential is NotFound", "[credentials]")
{
    auto store = makeCredentialStore();
    const std::string missing = "test/" + Uuid::generate().toString();

    auto secret = store->retrieve(missing);
    REQUIRE(secret.isError());
    REQUIRE(secret.status().code() == ErrorCode::NotFound);
    REQUIRE_FALSE(store->contains(missing));
}

TEST_CASE("a secret with no user name round-trips", "[credentials]")
{
    auto store = makeCredentialStore();
    ScopedTarget target{store};

    REQUIRE(store->store(target.name(), "", SecureString{"key-material"}).isOk());
    auto user = store->userNameFor(target.name());
    REQUIRE(user.isOk());
    REQUIRE(user.value().empty());
    REQUIRE(store->retrieve(target.name()).value().equals("key-material"));
}

TEST_CASE("an empty target is rejected", "[credentials]")
{
    auto store = makeCredentialStore();
    REQUIRE(store->store("", "user", SecureString{"x"}).isError());
}

TEST_CASE("an oversized secret is rejected rather than truncated",
          "[credentials][security]")
{
    auto store = makeCredentialStore();
    ScopedTarget target{store};

    // The vault blob limit is 5*512 bytes; a larger secret must fail loudly so
    // a key is never silently half-stored.
    const std::string huge(4096, 'A');
    REQUIRE(store->store(target.name(), "user", SecureString{huge}).isError());
}

TEST_CASE("target names are namespaced consistently", "[credentials]")
{
    // The prefix is applied idempotently, so a caller that already passes a
    // prefixed name reaches the same entry as one that passes the bare name.
    auto store = makeCredentialStore();
    const std::string bare = "test/" + Uuid::generate().toString();

    REQUIRE(store->store(bare, "user", SecureString{"v"}).isOk());
    REQUIRE(store->contains(credentialTargetPrefix() + bare));
    REQUIRE(store->erase(bare).isOk());
}
