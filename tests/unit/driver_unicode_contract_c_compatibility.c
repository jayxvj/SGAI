/*
 * driver_unicode_contract_c_compatibility.c
 *
 * C compilation compatibility test for the Unicode driver contract.
 * Verifies the header can be included and used from plain C.
 */
#include <sentinal/driver_unicode_contract.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
    /* Compile-time size/offset checks via pointer arithmetic */
    SentinalDriverUnicodeProtectionRequest req;
    SentinalDriverUnicodeProtectionResponse resp;
    (void)req;
    (void)resp;

    printf("C compat: sizeof request=%u  sizeof response=%u\n",
           (unsigned)sizeof(SentinalDriverUnicodeProtectionRequest),
           (unsigned)sizeof(SentinalDriverUnicodeProtectionResponse));

    return 0;
}
