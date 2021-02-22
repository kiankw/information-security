#include "../include/encrypt_decrypt.h"
#include "../include/des.h"

#include <string.h>  // memset()
#include <stdlib.h>

unsigned int encrypt(unsigned char *ciphertext, unsigned char *plaintext, unsigned int len_input, unsigned char *key_8bytes) {
    unsigned char key_64bits[64];
    memset(key_64bits, 0, 64);
    for (unsigned int i = 0; i < 8; ++i) {
        unsigned char temp = key_8bytes[i];
        for (int k = 7; k >= 0; --k) {
            key_64bits[i * 8 + (unsigned int)k] = temp % 2 + '0';
            temp = temp / 2;
        }
    }
    unsigned int len = DESencrypt(ciphertext, plaintext, len_input, key_64bits);
    return len;
}
unsigned int decrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned int len_input, unsigned char *key_8bytes) {
    unsigned char key_64bits[64];
    memset(key_64bits, 0, 64);
    for (unsigned int i = 0; i < 8; ++i) {
        unsigned char temp = key_8bytes[i];
        for (int k = 7; k >= 0; --k) {
            key_64bits[i * 8 + (unsigned int)k] = temp % 2 + '0';
            temp = temp / 2;
        }
    }
    unsigned int len = DESdecrypt(plaintext, ciphertext, len_input, key_64bits);
    return len;
}
