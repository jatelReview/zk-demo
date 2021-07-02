#include "platon/platon.hpp"
#include "platon/crypto/bn256/bn256.hpp"
#include "platon/hash/mimc.hpp"
#include "common.hpp"

using namespace platon::crypto::bn256::g16;
using namespace platon::hash::mimc;

CONTRACT PrivacyArc20 : public platon::Contract
{
public:
    // commitment, amount, coinIndex, owner
    PLATON_EVENT2(create, const std::uint256_t&, std::uint256_t, uint64_t, const platon::bytes&)

    // nullifier
    PLATON_EVENT1(destory, const std::uint256_t&)

public:
    ACTION void init(const platon::Address &verify, const platon::Address &arc20)
    {
        // set owner address
        platon::Address owner = platon::platon_caller();
        ::platon_set_state((const platon::byte *)&kOwnerKey, sizeof(kOwnerKey),
                           (const platon::byte *)owner.data(), owner.size);

        // set verify address
        ::platon_set_state((const platon::byte *)&kVerifyKey, sizeof(kVerifyKey),
                           (const platon::byte *)verify.data(), verify.size);

        // set arc20 address
        ::platon_set_state((const platon::byte *)&kArc20Key, sizeof(kArc20Key),
                           (const platon::byte *)arc20.data(), arc20.size);
    }

    // mint
    void mint(const std::vector<std::uint256_t> &inputs, const Proof &proof, const platon::bytes &owner)
    {
        // verify
        platon::Address verify = GetVerify();
        auto res = platon::platon_call_with_return_value<bool>(verify, platon::u128(0), ::platon_gas(),
             "VerifyTx", inputs, proof, MINT);
        privacy_assert(res.second && res.first, "mint operation zk verification failed");

        // public input information
        std::uint256_t amount = inputs[0];
        std::uint256_t commitment = inputs[1];

        // update merkle tree
        commitments.self().insert(commitment);

        uint64_t leafIndex = merkleWidth - 1 + zCount.self()++;
        merkleNodes.self()[leafIndex] = commitment;
        std::uint256_t root = updatePathToRoot(leafIndex);
        roots.self().insert(root);

        // transfer
        platon::Address arc20 = GetArc20();
        res = platon::platon_call_with_return_value<bool>(arc20, platon::u128(0), ::platon_gas(),
             "TransferFrom", platon::platon_caller(), platon::platon_address(), amount);
        privacy_assert(res.second && res.first, "Failed to call the transferFrom method of the ARC20 contract across contracts");

        // event
        PLATON_EMIT_EVENT2(create, commitment, amount, leafIndex, owner);
    }

    // transfer
    void transfer(const std::vector<std::uint256_t> &inputs, const Proof &proof, const std::vector<platon::bytes> &owner)
    {
        // verify
        platon::Address verify = GetVerify();
        auto res = platon::platon_call_with_return_value<bool>(verify, platon::u128(0), ::platon_gas(),
             "VerifyTx", inputs, proof, TRANSFER);
        privacy_assert(res.second && res.first, "transfer operation zk verification failed");

        // public input information
        std::uint256_t nc = inputs[0];
        std::uint256_t nd = inputs[1];
        std::uint256_t ze = inputs[2];
        std::uint256_t zeAmount = inputs[3];
        std::uint256_t zf = inputs[4];
        std::uint256_t zfAmount = inputs[5];
        std::uint256_t inputRoot = inputs[6];

        // check
        privacy_assert(roots.self().end() != roots.self().find(inputRoot), "invalid merkle tree root");
        privacy_assert(nc != nd, "Repeated input");
        privacy_assert(ze != zf, "Repeated output");
        privacy_assert(nullifiers.self().end() == nullifiers.self().find(nc), "It has been spent");
        privacy_assert(nullifiers.self().end() == nullifiers.self().find(nd), "It has been spent");

        // update merkle tree and nullifiers
        nullifiers.self().insert(nc);
        nullifiers.self().insert(nd);
        commitments.self().insert(ze);

        uint64_t leafIndex = merkleWidth - 1 + zCount.self()++;
        merkleNodes.self()[leafIndex] = ze;
        updatePathToRoot(leafIndex);

        commitments.self().insert(zf);
        leafIndex = merkleWidth - 1 + zCount.self()++;
        merkleNodes.self()[leafIndex] = zf;
        std::uint256_t root = updatePathToRoot(leafIndex);
        roots.self().insert(root);

        // event
        PLATON_EMIT_EVENT2(create, ze, zeAmount, leafIndex - 1, owner[0]);
        PLATON_EMIT_EVENT2(create, zf, zfAmount, leafIndex, owner[1]);

        PLATON_EMIT_EVENT1(destory, nc);
        PLATON_EMIT_EVENT1(destory, nd);
    }

    // burn
    void burn(const std::vector<std::uint256_t> &inputs, const Proof &proof, 
        const platon::Address &payTo)
    {
        // verify
        platon::Address verify = GetVerify();
        auto res = platon::platon_call_with_return_value<bool>(verify, platon::u128(0), ::platon_gas(),
             "VerifyTx", inputs, proof, BURN);
        privacy_assert(res.second && res.first, "burn operation zk verification failed");

        // public input information
        std::uint256_t value = inputs[0];
        std::uint256_t nc = inputs[1];
        std::uint256_t inputRoot = inputs[2];

        // check
        privacy_assert(roots.self().end() != roots.self().find(inputRoot), "invalid merkle tree root");
        privacy_assert(nullifiers.self().end() == nullifiers.self().find(nc), "It has been spent");

        // update merkle tree and nullifiers
        nullifiers.self().insert(nc);

        // transfer
        platon::Address arc20 = GetArc20();
        res = platon::platon_call_with_return_value<bool>(arc20, platon::u128(0), ::platon_gas(),
             "Transfer", payTo, value);
        privacy_assert(res.second && res.first, "Failed to call the Transfer method of the ARC20 contract across contracts");

        // event
        PLATON_EMIT_EVENT1(destory, nc);
    }

private:
    // get address of verify
    platon::Address GetVerify()
    {
        platon::Address addr;
        ::platon_get_state((const platon::byte *)&kVerifyKey, sizeof(kVerifyKey),
                           addr.data(), addr.size);
        return addr;
    }

    // get address of arc20
    platon::Address GetArc20()
    {
        platon::Address addr;
        ::platon_get_state((const platon::byte *)&kArc20Key, sizeof(kArc20Key),
                           addr.data(), addr.size);
        return addr;
    }

private:
    // key
    constexpr static uint64_t kOwnerKey = platon::name_value("owner");
    constexpr static uint64_t kVerifyKey = platon::name_value("verify");
    constexpr static uint64_t kArc20Key = platon::name_value("arc20");

private:
    // merkle tree
    constexpr static uint64_t merkleWidth = 4294967296ul; //2^32
    constexpr static uint32_t merkleDepth = 33;

    std::uint256_t updatePathToRoot(uint64_t p)
    {
        uint64_t s = 0, t = 0;
        for (uint64_t r = merkleDepth - 1; r > 0; r--)
        {
            if (p % 2 == 0)
            {
                s = p - 1;
                t = (p - 1) / 2;

                const std::uint256_t &sHash = merkleNodes.self()[s];
                const std::uint256_t &pHash = merkleNodes.self()[p];

                std::vector<std::uint256_t> data {sHash, pHash};
                merkleNodes.self()[t] = Mimc::Hash(data, 0);
            }
            else
            { //p odd index in M
                s = p + 1;
                t = p / 2;

                const std::uint256_t &pHash = merkleNodes.self()[p];
                const std::uint256_t &sHash = merkleNodes.self()[s];
                std::vector<std::uint256_t> data {pHash, sHash};

                merkleNodes.self()[t] = Mimc::Hash(data, 0);
            }
            p = t;
        }

        return merkleNodes.self()[0];
    }

private:
    platon::StorageType<"count"_n, uint64_t> zCount;                                    //remembers the number of commitments we hold
    platon::StorageType<"merkleNodes"_n, std::map<uint64_t, std::uint256_t>> merkleNodes; //the entire Merkle Tree of nodes
    platon::StorageType<"roots"_n, std::set<std::uint256_t>> roots;                        //holds each root we've calculated;
    platon::StorageType<"commitments"_n, std::set<std::uint256_t>> commitments;            //array holding the commitments.
    platon::StorageType<"nullifiers"_n, std::set<std::uint256_t>> nullifiers;              //store nullifiers
};

PLATON_DISPATCH(PrivacyArc20, (init)(mint)(transfer)(burn))
