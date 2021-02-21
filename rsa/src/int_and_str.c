#include "int_and_str.h"

#include <stdio.h>

/*
I2OSP converts a nonnegative integer to an octet string of a
specified length.

I2OSP (x, xLen)
Input:
    x nonnegative integer to be converted
    xLen intended length of the resulting octet string
Output:
    X corresponding octet string of length xLen
Error:
    "integer too large"
*/
String * I2OSP(const mpz_t tx, const int xlen) {
	mpz_t x; mpz_init(x);
	mpz_set(x, tx);
	mpz_t d256; mpz_init(d256);
	mpz_set_ui(d256, 256);
	mpz_t pow256; mpz_init(pow256);
    mpz_pow_ui(pow256, d256, (unsigned long)xlen);

    if (mpz_cmp(x, pow256) >= 0) {
        printf("Error: integer too large!\n");
        return NULL;
    }
    mpz_clear(pow256);

	mpz_t remainder; mpz_init(remainder);
    String *ans = initstr(xlen);
    for (int i = 0; i < xlen; ++i) {
        if (mpz_cmp_ui(x, 0) <= 0) {
            break;
        }
        mpz_fdiv_qr(x, remainder, x, d256);
        ans->data[xlen - i - 1] = mpz_get_ui(remainder);
    }
    mpz_clear(remainder);
    mpz_clear(d256);
	mpz_clear(x);

    return ans;
}

/*
OS2IP converts an octet string to a nonnegative integer.

OS2IP (X)
Input:
    X octet string to be converted
Output:
    x corresponding nonnegative integer
*/
void OS2IP(mpz_t ans, const String *X) {
    for (int i = 0; i < X->len; ++i) {
        mpz_mul_ui(ans, ans, 256);
        mpz_add_ui(ans, ans, (unsigned long)(X->data[i]));
    }
}
