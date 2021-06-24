#include "platon/platon.hpp"
#include "platon/crypto/bn256/bn256.hpp"

CONTRACT PrivacyArc20 : public platon::Contract
{
public:
    // commitment, amount, coinIndex, owner
    PLATON_EVENT2(create, const platon::h256&, std::uint256_t, uint64_t, const bytes&)

    // nullifier
    PLATON_EVENT1(destory, const platon::h256&)

public:
    ACTION void init(const platon::Address &verify, const platon::Address &arc20)
    {
        // set owner address
        platon::Address owner = platon_caller();
        ::platon_set_state((const byte *)&kOwnerKey, sizeof(kOwnerKey),
                           (const byte *)owner.data(), owner.size);

        // set verify address
        ::platon_set_state((const byte *)&kVerifyKey, sizeof(kVerifyKey),
                           (const byte *)verify.data(), verify.size);

        // set arc20 address
        ::platon_set_state((const byte *)&kArc20Key, sizeof(kArc20Key),
                           (const byte *)arc20.data(), arc20.size);
    }

    // mint
    void mint(const std::vector<std::uint256_t> &inputs, const Proof &proof, const bytes &owner)
    {
        // verify
        platon::Address verify = GetVerify();
        bool result = verify.VerifyTx(inputs, proof);

        // public input information
        std::uint256_t amount = inputs[0];
        std::uint256_t commitment = inputs[1];

        // update merkle tree
        commitments.self().insert(commitment);

        uint64_t leafIndex = merkleWidth - 1 + zCount.self()++;
        merkleNodes.self()[leafIndex] = commitment;
        platon::h256 root = updatePathToRoot(leafIndex);
        roots.self().insert(root);

        // transfer
        platon::Address arc20 = GetArc20();
        auto res = platon::platon_call_with_return_value<bool>(arc20, u128(0), ::platon_gas(),
             "TransferFrom", platon_caller(), platon_address(), amount);
        privacy_assert(res.second && res.first, "Failed to call the transferFrom method of the ARC20 contract across contracts");

        // event
        PLATON_EMIT_EVENT2(create, commitment, amount, leafIndex, owner);
    }

    // transfer
    void transfer(const std::vector<std::uint256_t> &inputs, const Proof &proof, const std::vector<bytes> &owner)
    {
        // verify
        platon::Address verify = GetVerify();
        bool result = verify.VerifyTx(inputs, proof);

        // public input information
        std::uint256_t nc = input[0];
        std::uint256_t nd = input[1];
        std::uint256_t ze = input[2];
        std::uint256_t zeAmount = input[3];
        std::uint256_t zf = input[4];
        std::uint256_t zfAmount = input[5];
        std::uint256_t inputRoot = input[6];

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
        platon::h256 root = updatePathToRoot(leafIndex);
        roots.self().insert(root);

        // event
        PLATON_EMIT_EVENT2(create, ze, zeAmount, leafIndex - 1, owner[0]);
        PLATON_EMIT_EVENT2(create, zf, zfAmount, leafIndex, owner[1]);

        PLATON_EMIT_EVENT1(destory, nc)
        PLATON_EMIT_EVENT1(destory, nd)
    }

    // burn
    void burn(const std::vector<std::uint256_t> &inputs, const Proof &proof, const bytes &owner)
    {
        // verify
        platon::Address verify = GetVerify();
        bool result = verify.VerifyTx(inputs, proof);

        // public input information
        std::uint256_t payTo = input[0];
        std::uint256_t value = input[1];
        std::uint256_t nc = input[2];
        std::uint256_t inputRoot = input[3];

        // check
        privacy_assert(roots.self().end() != roots.self().find(inputRoot), "invalid merkle tree root");
        privacy_assert(nullifiers.self().end() == nullifiers.self().find(nc), "It has been spent");

        // update merkle tree and nullifiers
        nullifiers.self().insert(nc);

        // transfer
        platon::Address arc20 = GetArc20();
        auto res = platon::platon_call_with_return_value<bool>(arc20, u128(0), ::platon_gas(),
             "Transfer", payTo, value);
        privacy_assert(res.second && res.first, "Failed to call the Transfer method of the ARC20 contract across contracts");

        // event
        PLATON_EMIT_EVENT1(destory, nc)
    }

private:
    // get address of verify
    platon::Address GetVerify()
    {
        platon::Address addr;
        ::platon_get_state((const byte *)&kVerifyKey, sizeof(kVerifyKey),
                           addr.data(), addr.size);
        return addr;
    }

    // get address of arc20
    platon::Address GetArc20()
    {
        platon::Address addr;
        ::platon_get_state((const byte *)&kArc20Key, sizeof(kArc20Key),
                           addr.data(), addr.size);
        return addr;
    }

private:
    // type
    struct Proof
    {
        G1 a;
        G2 b;
        G1 c;
    };

private:
    // key
    constexpr uint64_t kOwnerKey = "owner"_n;
    constexpr uint64_t kVerifyKey = "verify"_n;
    constexpr uint64_t kArc20Key = "arc20"_n;

private:
    // merkle tree
    constexpr static uint64_t merkleWidth = 2 << 32;
    constexpr static uint32_t merkleDepth = 33;

    platon::h256 updatePathToRoot(uint64_t p)
    {
        uint64_t s = 0, t = 0;
        for (uint64_t r = merkleDepth - 1; r > 0; r--)
        {
            if (p % 2 == 0)
            {
                s = p - 1;
                t = (p - 1) / 2;

                const platon::h256 &sHash = merkleNodes.self()[s];
                const platon::h256 &pHash = merkleNodes.self()[p];

                std::vector<platon::byte> data(sHash.size + pHash.size);
                std::copy(sHash.begin(), sHash.end(), data.begin());
                std::vector<platon::byte>::iterator iter = data.begin();
                std::advance(iter, sHash.size)
                    std::copy(pHash.begin(), pHash.end(), iter);

                merkleNodes.self()[t] = platon::platon_sha3(data);
            }
            else
            { //p odd index in M
                s = p + 1;
                t = p / 2;

                const platon::h256 &pHash = merkleNodes.self()[p];
                const platon::h256 &sHash = merkleNodes.self()[s];

                std::vector<platon::byte> data(pHash.size + sHash.size);
                std::copy(pHash.begin(), pHash.end(), data.begin());
                std::vector<platon::byte>::iterator iter = data.begin();
                std::advance(iter, pHash.size)
                    std::copy(sHash.begin(), sHash.end(), iter);

                merkleNodes.self()[t] = platon::platon_sha3(data);
            }
            p = t;
        }

        return merkleNodes.self()[0];
    }

private:
    platon::StorageType<"count"_n, uint64_t> zCount;                                    //remembers the number of commitments we hold
    platon::StorageType<"merkleNodes"_n, std::map<uint64_t, platon::h256>> merkleNodes; //the entire Merkle Tree of nodes
    platon::StorageType<"roots"_n, std::set<platon::256>> roots;                        //holds each root we've calculated;
    platon::StorageType<"commitments"_n, std::set<platon::256>> commitments;            //array holding the commitments.
    platon::StorageType<"nullifiers"_n, std::set<platon::256>> nullifiers;              //store nullifiers
};

PLATON_DISPATCH(PrivacyArc20, (init))
