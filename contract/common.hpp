#pragma once

#include <platon/platon.hpp>

class PrivacyRevert {
  PLATON_EVENT0(PrivacyRevertEvent, const std::string &)
 public:
  static void Revert(const std::string &log) {
    PrivacyRevert pr;
    pr.EmitRevert(log);
  }

 private:
  void EmitRevert(const std::string &log) {
    PLATON_EMIT_EVENT0(PrivacyRevertEvent, log);
  }
};

#define privacy_assert(A, ...)                                       \
  privacy_assert_aux(A, #A, __LINE__, __FILE__, __func__, \
                                ##__VA_ARGS__)

template <typename... Args>
inline void privacy_assert_aux(bool cond, const char *cond_str, unsigned line,
                               const char *file, const char *func,
                               Args &&... args) {
  if (!cond) {
    std::string all_info;
    platon::print(all_info, std::forward<Args>(args)...);
    platon::println("Assertion failed:", cond_str, "func:", func, "line:", line,
            "file:", file, all_info);
    PrivacyRevert::Revert(all_info);
    ::platon_revert();
  }
}

namespace platon {
namespace crypto {
namespace bn256 {
namespace g16 {

struct Proof {
    G1 a;
    G2 b;
    G1 c;
    PLATON_SERIALIZE(Proof, (a)(b)(c))
};

}  // namespace g16
}  // namespace bn256
}  // namespace crypto
}  // namespace platon

constexpr uint8_t MINT = 0;
constexpr uint8_t TRANSFER = 1;
constexpr uint8_t BURN = 2;