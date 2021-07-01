#include "platon/platon.hpp"
#include "platon/crypto/bn256/bn256.hpp"
#include "common.hpp"

namespace platon {
namespace crypto {
namespace bn256 {
namespace g16 {

namespace pairing {

/// Convenience method for a pairing check for two pairs.
bool PairingProd2(const G1 &a1, const G2 &a2, const G1 &b1, const G2 &b2) {
  std::array<G1, 2> g1{a1, b1};
  std::array<G2,2> g2{a2, b2};
  return bn256::pairing(g1,g2) == 0;
}
/// Convenience method for a pairing check for three pairs.
bool PairingProd3(const G1 &a1, const G2 &a2, const G1 &b1, const G2 &b2,
                  const G1 &c1, const G2 &c2) {
  std::array<G1, 3> g1 {a1, b1, c1};
  std::array<G2, 3> g2 {a2, b2, c2};
  return bn256::pairing(g1, g2) == 0;
}
/// Convenience method for a pairing check for four pairs.
bool PairingProd4(const G1 &a1, const G2 &a2, const G1 &b1, const G2 &b2,
                  const G1 &c1, const G2 &c2, const G1 &d1, const G2 &d2) {
  std::array<G1, 4> g1 {a1, b1, c1, d1};
  std::array<G2,4> g2 {a2, b2, c2, d2};
  return bn256::pairing(g1, g2) == 0;
}
};  // namespace pairing

struct VerifyingKey {
    G1 alpha;
    G2 beta;
    G2 gamma;
    G2 delta;
    std::vector<G1> gamma_abc;
};

namespace mint{
class Verifier {
 public:
  static VerifyingKey GetVerifyingKey() {
    return VerifyingKey{
        G1{std::uint256_t("0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10"), std::uint256_t("0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566")},
        G2(std::uint256_t("0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf"), std::uint256_t("0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00"), std::uint256_t("0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17"), std::uint256_t("0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90")),
        G2(std::uint256_t("0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2"), std::uint256_t("0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f"), std::uint256_t("0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41"), std::uint256_t("0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911")),
        G2(std::uint256_t("0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852"), std::uint256_t("0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2"), std::uint256_t("0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982"), std::uint256_t("0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86")),
        {G1(std::uint256_t("0x12bf279493189ea022d901f1137763af1ff76c27602b93e19ee0eb9c0a7177f3"), std::uint256_t("0x2dc4c8efbde47764f9ed1b4b58949957397f04bd5659782fb9e50c2849aa6eb6")),
        G1(std::uint256_t("0x2a552b0b2ead1d844cf2955c8724cbf3899561b2b7d14ec05797219560c9cd0a"), std::uint256_t("0x0792d3103858d496ab26e3f7cb6593409a55768a0828368fb154ef2ca63fafe8")),
        G1(std::uint256_t("0x23732b5815c5debb59394eadb496d0f99b6ed5d74de0f7ced6674ba67e04a6d6"), std::uint256_t("0x146455f09451001b27160a1f8bcf434a111c633bed94d24fd540da7b15e61113")),
        G1(std::uint256_t("0x09935b929fbc68dfe5bf63f25b346d3d70a8da6a27d8ddee98f96c80590ee4b0"), std::uint256_t("0x23282f4c255bfe754cd4699c341b9ebd39e1ded6f354044970974e4c4e233f51"))}
        };
  }

  static int Verify(const std::vector<std::uint256_t> &inputs,
                        const Proof &proof) {
    std::uint256_t snark_scalar_field =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"_uint256;
    VerifyingKey vk = GetVerifyingKey();
    platon_assert(inputs.size() + 1 == vk.gamma_abc.size());
    
    // Compute the linear combination vk_x
    G1 vk_x = G1{0, 0};
    for (int i = 0; i < inputs.size(); i++) {
      platon_assert(inputs[i] < snark_scalar_field);
      vk_x = Addition(
          vk_x, ScalarMul(vk.gamma_abc[i + 1], inputs[i]));
    }
    vk_x = Addition(vk_x, vk.gamma_abc[0]);

    if (!pairing::PairingProd4(proof.a, proof.b, Neg(vk_x),
                               vk.gamma, Neg(proof.c), vk.delta,
                               Neg(vk.alpha), vk.beta))
      return -1;
    return 0;
  }

  static bool VerifyTx(const std::array<std::uint256_t,2> &a, const std::array<std::array<std::uint256_t,2>,2> &b,
                const std::array<std::uint256_t,2> &c, const std::vector<std::uint256_t> &inputs) {
    Proof proof{G1{a[0], a[1]}, G2(b[0][1], b[0][0], b[1][1], b[1][0]),
                G1{c[0], c[1]}};

    return Verify(inputs, proof) == 0;
  }
};
} // namespace mint

namespace transfer{
class Verifier {
 public:
  static VerifyingKey GetVerifyingKey() {
    return VerifyingKey{
        G1{std::uint256_t("0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10"), std::uint256_t("0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566")},
        G2(std::uint256_t("0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf"), std::uint256_t("0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00"), std::uint256_t("0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17"), std::uint256_t("0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90")),
        G2(std::uint256_t("0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2"), std::uint256_t("0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f"), std::uint256_t("0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41"), std::uint256_t("0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911")),
        G2(std::uint256_t("0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852"), std::uint256_t("0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2"), std::uint256_t("0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982"), std::uint256_t("0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86")),
        {G1(std::uint256_t("0x2792f0ea4b92ebbc5c6153810d9a1a933e120b579c1cbc3d53af2315c8f8e93f"), std::uint256_t("0x15e368213c639ef54a53d22265a161b57f4264ad9c85e13372677a6a58a0bb75")),
        G1(std::uint256_t("0x293672746d6f5d0da659aa489be80097e659e41c9abba58e8c3259c681e088fc"), std::uint256_t("0x2ebe291044ea01b93d2ef72731a431a0c544fd1e16e68c28c80c0f050fc6e1ae")),
        G1(std::uint256_t("0x12ac29fb9afdeea68ff4ad88c182494ca00ec0693341fb9753ad23d07087fe6e"), std::uint256_t("0x2e1f8921c3ef9c2a65950b647921986b832fd155fb9a40a9999377d96eb7b526")),
        G1(std::uint256_t("0x20036ac27313dce397702687fc2cf2b42e7d1bab1383fe6a652ede400fd09be4"), std::uint256_t("0x1bfd3d53ac71f667819fdb5163e7e0add4f5155bf06e1df69151998f17052cd0")),
        G1(std::uint256_t("0x24bdc4adb3409c3b82c5cc4993b7829c21e77f6c9954a7ae19311d9d837df31b"), std::uint256_t("0x1260635047c8671d545cdd12a1e0b9d2983e147b355c2d518b00ecce6b7da6fc")),
        G1(std::uint256_t("0x089ddcded05a8a2522b44dbbaae5d1ef5c1e17994d9343bdcb68321f6a7f0ecd"), std::uint256_t("0x11e0984c973e9288158d8acde81ed3075204f1ccb85ef1c3c6b0579026959b82")),
        G1(std::uint256_t("0x089d46835b423ce598e584831ed20e166cdd353bea6eac1c6415307ed8d5254a"), std::uint256_t("0x1fee698159f867dd9aa5b7a8fa25e464d8a49fe117844bf8d1c5a6e22fd18845")),
        G1(std::uint256_t("0x146e5de663fcf0e536bd5521b5146a418129ee11d877a8c977ca52b23e06e1ef"), std::uint256_t("0x1e2f80c6a42fbd567a2a6a3d54684dcf847923c9d2b35a0404105039a3f40acf")),
        G1(std::uint256_t("0x1a29973f07db817dcee0af8b9e1141ed66f3348576475ad5c83ff0e960f927fa"), std::uint256_t("0x01dd94d04be43dba2a13568a37e33c4e37c791ea8352e485072a4bcf19a3f984")),
        G1(std::uint256_t("0x10a443adecf6cea23a5d58e6f8f394cce29343001709a65dec28ec43da1669b1"), std::uint256_t("0x28b1e5f82cb33f3c89a75c6df25220cffa8ba1462dd4917388a1d2fd052a78e0")),
        G1(std::uint256_t("0x2849484a90f2e724eec9daf1bbc7ea615d6259976e2d69bb48b62ca784bcc283"), std::uint256_t("0x20858ae80ca8778291db68102a4852cc96aabc2227e08fe55511cc318aff9270")),
        G1(std::uint256_t("0x056b067c12ff12321bf0d64df0d74c4cd44c7f8694a1fca7c8554f99b16a6fc4"), std::uint256_t("0x1560c88ef6ce216f7b7832230ca1eec2edabed750f508625fcd820183954cece"))}
        };
  }

  static int Verify(const std::vector<std::uint256_t> &inputs,
                        const Proof &proof) {
    std::uint256_t snark_scalar_field =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"_uint256;
    VerifyingKey vk = GetVerifyingKey();
    platon_assert(inputs.size() + 1 == vk.gamma_abc.size());
    
    // Compute the linear combination vk_x
    G1 vk_x = G1{0, 0};
    for (int i = 0; i < inputs.size(); i++) {
      platon_assert(inputs[i] < snark_scalar_field);
      vk_x = Addition(
          vk_x, ScalarMul(vk.gamma_abc[i + 1], inputs[i]));
    }
    vk_x = Addition(vk_x, vk.gamma_abc[0]);

    if (!pairing::PairingProd4(proof.a, proof.b, Neg(vk_x),
                               vk.gamma, Neg(proof.c), vk.delta,
                               Neg(vk.alpha), vk.beta))
      return -1;
    return 0;
  }

  static bool VerifyTx(const std::array<std::uint256_t,2> &a, const std::array<std::array<std::uint256_t,2>,2> &b,
                const std::array<std::uint256_t,2> &c, const std::vector<std::uint256_t> &inputs) {
    Proof proof{G1{a[0], a[1]}, G2(b[0][1], b[0][0], b[1][1], b[1][0]),
                G1{c[0], c[1]}};

    return Verify(inputs, proof) == 0;
  }
};

} // namespace transfer

namespace burn{
class Verifier {
 public:
  static VerifyingKey GetVerifyingKey() {
    return VerifyingKey{
        G1{std::uint256_t("0x1936c240636390dc823e3a728e94b208eb53c6756d81da57ec3425e05d43ac10"), std::uint256_t("0x2d70ff78e8216bf29d58923a686d9738278b8ce2fd822e197c85b09286d15566")},
        G2(std::uint256_t("0x2b4daf047abe2e7f0b311118c1b963b63695dc0d769cea78849604434de055bf"), std::uint256_t("0x29c13ecb6f33dbc4b3b8a02e2e255511ce4c26a8a2f299efcc94caf2de4fce00"), std::uint256_t("0x1da9020008df7f549751f8a251af3b2dc4a2ad3e0870de54acaedd9fc1b47e17"), std::uint256_t("0x25ea0d7e2b29de431b86a943db30dbf4d98f68df9ca8a9628d14d1591e817d90")),
        G2(std::uint256_t("0x011016e22ae045444f50fb80f246ec486c7e02af09132cd38c4fcf484983e4f2"), std::uint256_t("0x00e83c788c2878d1d5eba3ed49b0d81e4c0487dedc3e4d1c2baab5833785b62f"), std::uint256_t("0x05eb89e741ed5b5d611cebf92d1ed02cd6f3311089f0d400df7d9ced5a48fd41"), std::uint256_t("0x132a90a3b0d369ccd66e2a5ba04a935e44d8ad5dca93a76bba592a578130a911")),
        G2(std::uint256_t("0x065f6a3323a2abffd621fc263f348eb914904b68d5897729ae34a6b9d33f0852"), std::uint256_t("0x0c3b60f59d3bd50328a04c0ff6d979199685d0526f89f6ac29d6174ce24707a2"), std::uint256_t("0x26e7ebce2b44efef6b6315938e33f0a8ecc82dbad635c9efa681ed85bbb59982"), std::uint256_t("0x12e0f3721230a0f38f6c9913048d5230fd2615ef3ff7f6ee4b20dfe0bdea1a86")),
        {G1(std::uint256_t("0x2ccc9eaacc706641a8f3a26e72d867d2db2e3a75df02aeb4c032ec532a0fb7d5"), std::uint256_t("0x05586f13db625ef2cf8ed837d4a66fcbcbbe27e85273b2df7d3e49ce56ecedea")),
        G1(std::uint256_t("0x1151296e6fe7e531d60130d5970ffa593bab0baae656957bd158ce8de6f8e092"), std::uint256_t("0x0b309465c14535ea81fa0cdea7aff964fe1d14ddee4af806acb99dab910c2d35")),
        G1(std::uint256_t("0x2e4d7840063df68bee04fd12aa849540171ac8a3ce4895fe4a0b9482c98329d0"), std::uint256_t("0x00de8b14bf0dde5bbc5fc439537566a551952984845a52be6afc69b7fda996a6")),
        G1(std::uint256_t("0x0eec22143182bed9ca89ec3be2141fd3cc59fd3a01cdc687853428af448c95c1"), std::uint256_t("0x2142232aa634f79b3c3ac03086102f9929548356f720e16082757f4c66d10a44")),
        G1(std::uint256_t("0x0abc72fa086681d21d6d5e41a353b58bf72bb2e4b6433cef0cc016827b4542de"), std::uint256_t("0x2d6a656e4d868dbc105e800ba143a9f60be2a6e5e620c89f0b42a94eaa8f0ce5"))}
        };
  }

  static int Verify(const std::vector<std::uint256_t> &inputs,
                        const Proof &proof) {
    std::uint256_t snark_scalar_field =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"_uint256;
    VerifyingKey vk = GetVerifyingKey();
    platon_assert(inputs.size() + 1 == vk.gamma_abc.size());
    
    // Compute the linear combination vk_x
    G1 vk_x = G1{0, 0};
    for (int i = 0; i < inputs.size(); i++) {
      platon_assert(inputs[i] < snark_scalar_field);
      vk_x = Addition(
          vk_x, ScalarMul(vk.gamma_abc[i + 1], inputs[i]));
    }
    vk_x = Addition(vk_x, vk.gamma_abc[0]);

    if (!pairing::PairingProd4(proof.a, proof.b, Neg(vk_x),
                               vk.gamma, Neg(proof.c), vk.delta,
                               Neg(vk.alpha), vk.beta))
      return -1;
    return 0;
  }

  static static bool VerifyTx(const std::array<std::uint256_t,2> &a, const std::array<std::array<std::uint256_t,2>,2> &b,
                const std::array<std::uint256_t,2> &c, const std::vector<std::uint256_t> &inputs) {
    Proof proof{G1{a[0], a[1]}, G2(b[0][1], b[0][0], b[1][1], b[1][0]),
                G1{c[0], c[1]}};

    return Verify(inputs, proof) == 0;
  }
};
} // namespace burn

}  // namespace g16
}  // namespace bn256
}  // namespace crypto
}  // namespace platon

using namespace platon::crypto::bn256::g16;

CONTRACT Verify : public platon::Contract{
    public:
        ACTION void init(){}
        CONST bool VerifyTx(const std::vector<std::uint256_t> &inputs, const Proof &proof, uint8_t tranferType){
            switch (tranferType) {
                case MINT:
                    return mint::Verifier::Verify(inputs, proof);
                case TRANSFER:
                    return transfer::Verifier::Verify(inputs, proof);
                case BURN:
                    return burn::Verifier::Verify(inputs, proof);
            }

            return false;
        }
};

PLATON_DISPATCH(Verify, (init)(VerifyTx))