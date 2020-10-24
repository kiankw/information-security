#include "rsa.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>


/*
RSA Decryption Primitive

RSADP (K, c)
Input:
    K RSA private key, where K has the following forms: a pair (n, d)
Output:
    m message representative, an integer between 0 and n - 1
Error:
    "ciphertext representative out of range"
Assumption:
    RSA private key K is valid
*/
void RSADP(mpz_t m, mpz_t n, mpz_t d, mpz_t c) {
    if (c <= 0 || mpz_cmp(c, n) >= 0) {
        printf("Error: ciphertext representative out of range!\n");
        return ;
    }
    mpz_powm(m, c, d, n);
}

String * separate_M_From(String *EM) {
	int len = lenstr(EM);
	int start = len - 1;
	for (; start >= 0; --start) {
		if (EM->data[start] == 0)
			break;
	}
    ++start;
    String *M = initstr(len - start);
    for (int i = 0; i < len - start; ++i) {
        M->data[i] = EM->data[start + i];
    }
    return M;
}

/*
RSAES-PKCS1-V1_5-DECRYPT (K, C)
Input:
    K recipient’s RSA private key
    C ciphertext to be decrypted, an octet string of length k, where k is the length in octets of the RSA modulus n
Output:
    M message, an octet string of length at most k - 11
Error:
    "decryption error"
*/

String * RSAAES_PKCS1_v1_5_DECRYPT(mpz_t n, mpz_t d, const String *C, int K) {
	int k = K / 8;
    /* Length checking: If the length of the ciphertext C is not k octets (or if k < 11), output "decryption error" and stop. */
    if (C->len < 11) {
        printf("Error: decryption error!\n");
        return NULL;
    }
	mpz_t c; mpz_init(c);
    /* Convert the ciphertext C to an integer ciphertext representative c */
    OS2IP(c, C);
	mpz_t m; mpz_init(m);
    /* Apply the RSADP decryption primitive to the RSA private key (n, d) and the ciphertext representative c to produce an integer message representative m */
    RSADP(m, n, d, c);
	mpz_clear(c);

    /* If RSADP outputs "ciphertext representative out of range" (meaning that c >= n), output "decryption error" and stop */
    if (mpz_cmp_ui(m, 0) == 0) {
        printf("Error: decryption error!\n");
        return NULL;
    }
    /* Convert the message representative m to an encoded message EM of length k octets  */
    String *EM = I2OSP(m, k);
	
	mpz_clear(m);
    /* EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an octet string PS consisting of nonzero octets and a message M */
    String *M = separate_M_From(EM);
#if 0
    /* debug print */
	displaystr(EM);
	putchar(10);
	displaystr(M);
#endif
    destorystr(EM);
    return M;
}


String * decrypt(const String *C, const int k) {
	String *ans = RSAAES_PKCS1_v1_5_DECRYPT(n, d, C, k);
	return ans;
}
