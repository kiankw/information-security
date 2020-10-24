#ifndef INT_AND_STR_H
#define INT_AND_STR_H

#include "str.h"

#include <gmp.h>

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
String * I2OSP(const mpz_t tx, const int xlen);

/*
OS2IP converts an octet string to a nonnegative integer.

OS2IP (X)
Input:
    X octet string to be converted
Output:
    x corresponding nonnegative integer
*/
void OS2IP(mpz_t ans, const String *X);

#endif // INT_AND_STR_H
