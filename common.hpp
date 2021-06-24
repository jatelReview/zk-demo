#pragma once

#include "platon/platon.h"

#define privacy_assert(A, ...)                                       \
  ::privacy::privacy_assert_aux(A, #A, __LINE__, __FILE__, __func__, \
                                ##__VA_ARGS__)

template <typename... Args>
inline void privacy_assert_aux(bool cond, const char *cond_str, unsigned line,
                               const char *file, const char *func,
                               Args &&... args) {
  if (!cond) {
    std::string all_info;
    print(all_info, std::forward<Args>(args)...);
    println("Assertion failed:", cond_str, "func:", func, "line:", line,
            "file:", file, all_info);
    PrivacyRevert::Revert(all_info);
    ::platon_revert();
  }
}