#include "rsa.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

/*
RSA Encryption Primitive

RSAEP ((n, e), m)
Input:
    (n, e) RSA public key
    m message representative, an integer between 0 and n - 1
Output:
    c ciphertext representative, an integer between 0 and n - 1
Error:
    "message representative out of range"
Assumption:
    RSA public key (n, e) is valid
*/
void RSAEP(mpz_t c, mpz_t n, mpz_t e, mpz_t m) {
    if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, n) >= 0) {
        printf("Error: message representative out of range!\n");
        return ;
	}
    mpz_powm(c, m, e, n);
}
String * genePS(int len) {
    String *PS = initstr(len);
    srand(time(NULL));
    for (int i = 0; i < len; ++i) {
        PS->data[i] = (unsigned char)(1 + rand() % 255);
    }
    return PS;
}

/*
RSAES-PKCS1-V1_5-ENCRYPT ((n, e), M)
Input:
    (n, e) recipient’s RSA public key (k denotes the length in octets of the modulus n)
    M message to be encrypted, an octet string of length mLen, where mLen <= k - 11
Output:
    C ciphertext, an octet string of length k
Error:
    "message too long"
*/

String * RSAAES_PKCS1_v1_5_ENCRYPT(mpz_t n, mpz_t e, const String *M, int K) {
	/* Length checking: If mLen > k - 11, output "message too long" and stop. */
    int mlen = lenstr(M);
	int k = K / 8;
    if (mlen > k - 11) {
        printf("Error: message too long!\n");
        return NULL;
    }
    /* Generate an octet string PS of length k - mLen - 3 consisting of pseudo-randomly generated nonzero octets. The length of PS will be at least eight octets. */
    String *PS = genePS(k - mlen - 3);
    String *octet0 = initstr(1);
    octet0->data[0] = 0;
    String *octet2 = initstr(1);
    octet2->data[0] = 2;
    String *EM = initstr(0);
    /* Concatenate PS, the message M, and other padding to form an encoded message EM of length k octets as
    EM = 0x00 || 0x02 || PS || 0x00 || M. */
    catstr(catstr(catstr(catstr(catstr(EM, octet0), octet2), PS), octet0), M);

	mpz_t m; mpz_init(m);
    /* Convert the encoded message EM to an integer message representative m */
    OS2IP(m, EM);
#if 0
    /* debug print */
	displaystr(M); putchar(10);
	displaystr(EM); putchar(10);
	gmp_printf("%Zx\n", m);
#endif
	mpz_t c; mpz_init(c);
#if 0
    /* debug print */
	gmp_printf("%Zx\n\n", n);
	gmp_printf("%Zx\n\n", e);
	gmp_printf("%Zx\n\n", m);
#endif
    /* Apply the RSAEP encryption primitive to the RSA public key (n, e) and the message representative m to produce an integer ciphertext representative c */
    RSAEP(c, n, e, m);
	mpz_clear(m);
    /* Convert the ciphertext representative c to a ciphertext C of length k octets */
	String *C = I2OSP(c, k);

    destorystr(EM);
    destorystr(PS);
    destorystr(octet0);
    destorystr(octet2);
	return C;
}

String * encrypt(const String *M, const int k) {
	String *ans = RSAAES_PKCS1_v1_5_ENCRYPT(n, e, M, k);
	return ans;
}

