#ifndef DES_H
#define DES_H

#include <stdio.h>

unsigned long long DESencrypt(unsigned char * ciphertext, unsigned char*plaintext, unsigned long long len_input, unsigned char *key_64bits);
unsigned long long DESdecrypt(unsigned char *plaintext, unsigned char *ciphertext, unsigned long long len_input, unsigned char *key_64bits);

#endif // DES_H
