#include "md5.h"
#include "hmac-md5.h"

#include <stdio.h>
#include <stdlib.h>

void MD5_manuallyInput(void);
void MD5_example1(void);
void MD5_example2(void);
void MD5_example3(void);
void MD5_example4(void);
void MD5_example5(void);

void HMAC_MD5_manuallyInput(void);
void HMAC_MD5_example1(void);

int main() {
//    MD5_manuallyInput();
//    MD5_example1();
//    MD5_example2();
//    MD5_example3();
//    MD5_example4();
//    MD5_example5();

    HMAC_MD5_manuallyInput();
//    HMAC_MD5_example1();
    return 0;
}

void MD5_manuallyInput(void) {
    unsigned long long len = 0;
    printf("please input the len    : ");
    scanf("%lld", &len);
    getchar();

    unsigned char *input = (unsigned char *) malloc(len * sizeof (unsigned char));
    printf("please input the message: ");

    for (unsigned int i = 0; i < len; ++i) {
        scanf("%c", input + i);
    }
    getchar();

    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);
    printf("The MD5 : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
void MD5_example1(void) {
    putchar(10);
    unsigned long long len = 7;
    unsigned char input[58] = "1234567890123456789012345678901234567890123456789012345678";
    printf("message: ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);
    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);

    printf("MD5    : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
void MD5_example2(void) {
    putchar(10);
    unsigned long long len = 0;
    unsigned char *input = NULL;
    printf("message: ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);
    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);

    printf("MD5    : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
void MD5_example3(void) {
    putchar(10);
    unsigned long long len = 55;
    unsigned char input[58] = "1234567890123456789012345678901234567890123456789012345678";
    printf("message: ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);
    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);

    printf("MD5    : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
void MD5_example4(void) {
    putchar(10);
    unsigned long long len = 56;
    unsigned char input[58] = "1234567890123456789012345678901234567890123456789012345678";
    printf("message: ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);
    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);

    printf("MD5    : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
void MD5_example5(void) {
    putchar(10);
    unsigned long long len = 58;
    unsigned char input[58] = "1234567890123456789012345678901234567890123456789012345678";
    printf("message: ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);
    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    MD5(output, input, len);

    printf("MD5    : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}

void HMAC_MD5_manuallyInput(void) {
    unsigned int keylen = 0;
    printf("please input the len of key    : ");
    scanf("%d", &keylen);
    getchar();

    unsigned char *key = (unsigned char *) malloc(keylen * sizeof (unsigned char));
    printf("please input the key           : ");
    for (unsigned int i = 0; i < keylen; ++i) {
        scanf("%c", key + i);
    }
    getchar();

    unsigned long long len = 0;
    printf("Please input the len of message: ");
    scanf("%lld", &len);
    getchar();

    unsigned char *input = (unsigned char *) malloc(len * sizeof (unsigned char));
    printf("Please input the message       : ");
    for (unsigned int i = 0; i < len; ++i) {
        scanf("%c", input + i);
    }
    getchar();

    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    HMAC_MD5(output, key, keylen, input, len);
    printf("The HMAC_MD5 : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
    free(input);
    free(key);
}
void HMAC_MD5_example1(void) {
    putchar(10);
    unsigned int keylen = 3;
    unsigned long long len = 7;
    unsigned char key[12] = "abcdefghijkl";
    unsigned char input[58] = "1234567890123456789012345678901234567890123456789012345678";

    printf("key       : ");
    for (unsigned int i = 0; i < keylen; ++i) {
        printf("%c", key[i]);
    }
    putchar(10);

    printf("message   : ");
    for (unsigned int i = 0; i < len; ++i) {
        printf("%c", input[i]);
    }
    putchar(10);

    unsigned char* output = (unsigned char *) malloc(16 * sizeof(unsigned char));
    HMAC_MD5(output, key, keylen, input, len);
    printf("HMAC_MD5  : ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", output[i]);
    }
    putchar(10);

    free(output);
}
