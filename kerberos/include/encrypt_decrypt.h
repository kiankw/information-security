#ifndef ENCRYPT_DECRYPT_H
#define ENCRYPT_DECRYPT_H

unsigned int encrypt(unsigned char *ciphertext, unsigned char*plaintext, unsigned int len_input, unsigned char *key_8bytes);
unsigned int decrypt(unsigned char *plaintext, unsigned char*ciphertext, unsigned int len_input, unsigned char *key_8bytes);

#endif // ENCRYPT_DECRYPT_H
