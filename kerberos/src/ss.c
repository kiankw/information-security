#include "../include/message.h"
#include "../include/ss.h"
#include "../include/encrypt_decrypt.h"

#include <fcntl.h>  // open(), O_RDONLY
#include <stdio.h>
#include <stdlib.h>  // malloc()
#include <string.h>  // memset()
#include <sys/stat.h>  // umask(), mkfifo()
#include <unistd.h>  // read(), close()

int main() {
    umask(0);
    if (mkfifo("../pip/pip-ss",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }
    printf("This is SS!\n");
    printf("Please waiting...\n");

    unsigned char *msgE = (unsigned char *) malloc (LEN_MSG_E * sizeof(unsigned char)); memset(msgE, 0, LEN_MSG_E);
    unsigned char *msgG = (unsigned char *) malloc (LEN_MSG_G * sizeof(unsigned char)); memset(msgG, 0, LEN_MSG_G);
    unsigned char *msgH = (unsigned char *) malloc (LEN_MSG_H * sizeof(unsigned char)); memset(msgH, 0, LEN_MSG_H);

    unsigned char *K_SS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); init_K_SS(K_SS);
    unsigned char *K_CLient_SS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); memset(K_CLient_SS, 0, LEN_KEY);
    unsigned char *client_ID = (unsigned char *) malloc (LEN_ID * sizeof(unsigned char)); memset(client_ID, 0, LEN_ID);

    time_t timestamp = -1;

    receive_from_client(msgE, LEN_MSG_E, msgG, LEN_MSG_G);
    printf("\n*************************************************************************\n");
    printf("    Receive :\n");

    printf("        msgE :");
    for (int i = 0; i < LEN_MSG_E; ++i) {
        printf("%02x", msgE[i]);
    }
    putchar(10);
    analysis_msgE(K_CLient_SS, msgE, K_SS);
    printf("            K_CLient_SS :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_CLient_SS[i]);
    }
    putchar(10);
    
    printf("        msgG :");
    for (int i = 0; i < LEN_MSG_G; ++i) {
        printf("%02x", msgG[i]);
    }
    putchar(10);
    analysis_msgG(client_ID, &timestamp, msgG, K_CLient_SS);
    printf("            client_ID      :%x\n", client_ID[0]);
    printf("            timestamp      :%ld\n", timestamp);

    printf("    Send :\n");
    timestamp += 1;
    gene_msgH(msgH, client_ID, &timestamp, K_CLient_SS);
    printf("        msgH :");
    for (int i = 0; i < LEN_MSG_H; ++i) {
        printf("%02x", msgH[i]);
    }
    putchar(10);
    printf("            client_ID      :%x\n", client_ID[0]);
    printf("            timestamp      :%ld\n", timestamp);
    send_to_client(msgH, LEN_MSG_H, NULL, 0);
    printf("*************************************************************************\n\n");

    free(client_ID);
    free(K_CLient_SS);
    free(K_SS);
    free(msgH);
    free(msgG);
    free(msgE);
    return 0;
}

void init_K_SS(unsigned char *K_SS) {
    K_SS[0] = 0x4e + 3;
    K_SS[1] = 0xee + 3;
    K_SS[2] = 0xbc + 3;
    K_SS[3] = 0x94 + 3;
    K_SS[4] = 0xc0 + 3;
    K_SS[5] = 0x49 + 3;
    K_SS[6] = 0x33 + 3;
    K_SS[7] = 0x05 + 3;
    K_SS[8] = 0xaf + 3;
}

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2) {
    int rfd = open("../pip/pip-ss",O_RDONLY);
    if (rfd < 0) {
        ERR_EXIT("open");
    }
    read(rfd, msg, len_msg);
    if (len_msg2) read(rfd, msg2, len_msg2);
    close(rfd);
    return 0;
}

void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2) {
    int wfd = open("../pip/pip-client3", O_WRONLY);
    if (wfd < 0) {
        ERR_EXIT("open");
    }
    write(wfd, msg, len_msg);
    if (len_msg2) write(wfd, msg2, len_msg2);
    close(wfd);
    return ;
}

void analysis_msgE(unsigned char *K_CLient_SS, unsigned char *msgE, unsigned char *K_SS) {
    int len_ST = 24;
    unsigned char *ST = (unsigned char *) malloc (len_ST * sizeof(unsigned char)); 
    memset(ST, 0, len_ST);
    memcpy(ST, msgE + LEN_ID, len_ST);

    unsigned char *ST_plaintext = (unsigned char *) malloc (256 * sizeof(unsigned char));
    memset(ST_plaintext, 1, len_ST);
    decrypt(ST_plaintext, ST, len_ST, K_SS);

    memcpy(K_CLient_SS, ST_plaintext + LEN_ID + LEN_IP + LEN_TIME, LEN_KEY);
    free(ST_plaintext);
    free(ST);
}

void analysis_msgG(unsigned char *client_ID, time_t *timestamp, unsigned char *msgG, unsigned char *K_CLient_SS) {
    unsigned char *msgG_plaintext = (unsigned char *) malloc (128 * sizeof(unsigned char));
    memset(msgG_plaintext, 0, LEN_MSG_G);

    decrypt(msgG_plaintext, msgG, LEN_MSG_G, K_CLient_SS);

    memcpy(client_ID, msgG_plaintext, LEN_ID);

    memcpy((void *)timestamp, msgG_plaintext + LEN_ID, LEN_TIME);
    free(msgG_plaintext);
    return ;
}

void gene_msgH(unsigned char *msgH, unsigned char *client_ID, time_t *timestamp , unsigned char *K_CLient_SS) {
    unsigned char *msgH_plaintext = (unsigned char *) malloc (LEN_MSG_H * sizeof(unsigned char)); 
    memset(msgH_plaintext, 0, LEN_MSG_H);
    int len_msgH_plaintext = 0;
    memcpy(msgH_plaintext + len_msgH_plaintext, client_ID, LEN_ID); len_msgH_plaintext += LEN_ID;
    memcpy(msgH_plaintext + len_msgH_plaintext, (void *)timestamp, LEN_TIME); len_msgH_plaintext += LEN_TIME;
    encrypt(msgH, msgH_plaintext, len_msgH_plaintext, K_CLient_SS);
    free(msgH_plaintext);
    return ;
}
