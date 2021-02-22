#include <stdio.h>
#include <string.h>  // strlen
#include <stdlib.h>  // malloc

#include "table.h"

char subkeys[17][49];

void permutation(char *ans, char *data, int *table);
void feistel(char *ans, char *r32, char *k48);
void sboxFunc(char *after, char *befor, int i);
void initSubkeys(char *key);
void shift(char *ans, char *data, int n);

void data_encryption_standard(char *des, char *res, int isEncrypt) {
    char afterIPtable[65];
    memset(afterIPtable, '0', 64);
    afterIPtable[64] = '\0';
    permutation(afterIPtable, res, ip_table);

    char L[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(L[i], '0', 32);
        L[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        L[0][i] = afterIPtable[i];
    }

    char R[17][33];
    for (int i = 0; i <= 16; ++i) {
        memset(R[i], '0', 32);
        R[i][32] = '\0';
    }
    for (int i = 0; i < 32; ++i) {
        R[0][i] = afterIPtable[i + 32];
    }

    for (int i = 1; i <= 16; ++i) {
        strcpy(L[i], R[i - 1]);
        char temp[33];
        memset(temp, '0', 32);
        temp[32] = '\0';

        if (isEncrypt) {
            feistel(temp, R[i - 1], subkeys[i]);
        } else {
            feistel(temp, R[i - 1], subkeys[17 - i]);
        }

        for (int j = 0; j < 32; ++j) {
            if (temp[j] == L[i - 1][j]) {
                R[i][j] = '0';
            } else {
                R[i][j] = '1';
            }
        }
    }

    for (int i = 0; i < 32; ++i) {
        afterIPtable[i] = R[16][i];
        afterIPtable[i + 32] = L[16][i];
    }
    permutation(des, afterIPtable, ip_1_table);
    return ;
}

int main(int argc, char * argv[]) {
    if(argc != 4) {
        printf("use format: > xx.out -de[-en] src dest\n");
        exit(-1);
    }

    FILE * pfr = fopen(argv[2], "rb+");
    if(NULL == pfr)
        exit(-1);

    FILE * pfw = fopen(argv[3], "wb+");
    if(NULL == pfw) {
        fclose(pfr);
        exit(-1);
    }

    FILE * pfkey = fopen("key.key", "rb+");
    if(NULL == pfkey) {
        fclose(pfw);
        fclose(pfr);
        exit(-1);
    }

    char key[65];
    key[64] = '\0';
    fread((void*)key, 1, 64, pfkey);
    for (int i = 0; i <= 16; ++i) {
        memset(subkeys[i], '0', 48);
        subkeys[i][48] = '\0';
    }
    initSubkeys(key);

    int n = 0;
    int readbuf[65];
    int writebuf[65];
    memset(readbuf, '0', 64);
    memset(writebuf, '0', 64);
    readbuf[64] = '\0';
    writebuf[64] = '\0';

    int isEncrypt = 0;
    if (strcmp(argv[1], "-en") == 0 || strcmp(argv[1], "-de") == 0) {
        if (strcmp(argv[1], "-en") == 0) {
            isEncrypt = 1;
        }
        while ((n = fread((void*)readbuf, 1, 64, pfr)) == 64) {
            data_encryption_standard(writebuf, readbuf, isEncrypt);
            fwrite((void*)writebuf, 1, 64, pfw);
        }
        if (n > 0) {
            int nByte = (64 - n) / 8;
            char temp[8];
            memset(temp, '0', 8);
            for (int i = 0, t = nByte; t; t /= 2 ) {
                temp[7 - i] = t % 2 + '0';
            }
            for (int i = 0; i < nByte; ++i) {
                for (int j = 0; j < 8; ++j) {
                    readbuf[n + i * 8 + j] = temp[j];
                }
            }
        } else {
            char *temp = "0000100000001000000010000000100000001000000010000000100000001000";

            strcpy(writebuf, temp);
        }
        data_encryption_standard(writebuf, readbuf, isEncrypt);
        fwrite((void*)writebuf, 1, 64, pfw);
    } else {
        printf("arg error!\n");
    }

    fclose(pfw);
    fclose(pfr);
    printf("Hello world is a great end!\n");
    return 0;
}

void permutation(char *ans, char *data, int *table) {
    int len = strlen(ans);
    for (int i = 0; i < len; ++i) {
        ans[i] = data[table[i] - 1];
    }
    return ;
}

void feistel(char *ans, char *r32, char *k48) {
    char e48[49];
    memset(e48, '0', 48);
    e48[48] = '\0';

    permutation(e48, r32, e_expand_table);

    for (int i = 0; i < 48; ++i) {
        if (e48[i] == k48[i]) {
            e48[i] = '0';
        } else {
            e48[i] = '1';
        }
    }

    char beforSbox[8][7];
    for (int i = 0; i < 8; ++i) {
        memset(beforSbox[i], '0', 6);
        beforSbox[i][6] = '\0';
    }
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 6; ++j) {
            beforSbox[i][j] = e48[i * 6 + j];
        }
    }

    char afterSbox[8][5];
    for (int i = 0; i < 8; ++i) {
        memset(afterSbox[i], '0', 4);
        afterSbox[i][4] = '\0';
    }
    for (int i = 0; i < 8; ++i) {
        sboxFunc(afterSbox[i], beforSbox[i], i);
    }

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            ans[i * 8 + j] = afterSbox[i][j];
        }
    }
    return ;
}

void sboxFunc(char *after, char *befor, int i) {
    int n = (befor[0] - '0') * 2 + befor[5] - '0';
    int m = 0;
    for (int i = 1; i <= 4; ++i) {
        m = m * 2 + befor[i] - '0';
    }
    int temp = sbox[i * 64 + n * 16 + m];
    for (int i = 4; i >= 1; --i) {
        after[i] = temp % 2 + '0';
        temp /= 2;
    }
    return ;
}

void initSubkeys(char *key) {
    char key56[57];
    memset(key56, ' ', 56);
    key56[56] = '\0';
    permutation(key56, key, pc1_table);

    char c[17][29];
    for (int i = 0; i <= 16; ++i) {
        memset(c[i], '0', 28);
        c[i][28] = '\0';
    }
    for (int i = 0; i < 28; ++i) {
        c[0][i] = key56[i];
    }

    char d[17][29];
    for (int i = 0; i <= 16; ++i) {
        memset(d[i], ' ', 28);
        d[i][28] = '\0';
    }
    for (int i = 0; i < 28; ++i) {
        d[0][i] = key56[i + 28];
    }

    for (int i = 1; i <= 16; ++i) {
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            shift(c[i], c[i - 1], 1);
            shift(d[i], d[i - 1], 1);
        } else {
            shift(c[i], c[i - 1], 2);
            shift(d[i], d[i - 1], 2);
        }
    }

    char oldkeys[17][57];
    for (int i = 0; i <= 16; ++i) {
        for (int j = 0; j < 28; ++j) {
            oldkeys[i][j] = c[i][j];
            oldkeys[i][j + 28] = d[i][j];
        }
        oldkeys[i][56] = '\0';
    }

    for (int i = 0; i <= 16; ++i) {
        permutation(subkeys[i], oldkeys[i], pc2_table);
    }
}

void shift(char *ans, char *data, int n) {
    int len = strlen(ans);
    for (int i = 0; i < len; ++i) {
        ans[i] = data[(i + n) % len];
    }
    return ;
}
