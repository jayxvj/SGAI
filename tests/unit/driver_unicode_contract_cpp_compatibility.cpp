/*
 * driver_unicode_contract_cpp_compatibility.cpp
 *
 * C++ compilation compatibility test for the Unicode driver contract.
 * Verifies the header can be included and used from C++.
 */
#include <sentinal/driver_unicode_contract.h>
#include <cstddef>
#include <iostream>

int main() {
    SentinalDriverUnicodeProtectionRequest req{};
    SentinalDriverUnicodeProtectionResponse resp{};
    (void)req;
    (void)resp;

    std::cout << "C++ compat: sizeof request=" << sizeof(req)
              << "  sizeof response=" << sizeof(resp) << "\n";
    return 0;
}
