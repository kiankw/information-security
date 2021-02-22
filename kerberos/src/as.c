#include "../include/message.h"
#include "../include/encrypt_decrypt.h"
#include "../include/as.h"

#include <fcntl.h>  // open(), O_RDONLY
#include <stdio.h>
#include <stdlib.h>  // malloc()
#include <string.h>  // memset()
#include <sys/stat.h>  // umask(), mkfifo()
#include <unistd.h>  // read(), close()

int main() {
    umask(0);
    if (mkfifo("../pip/pip-as",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }
    printf("This is AS!\n");
    printf("Please waiting...\n");

    unsigned char request[1024];
    unsigned char K_Client[LEN_KEY]; init_K_Client(K_Client);
    unsigned char K_Client_TGS[LEN_KEY]; init_K_Client_TGS(K_Client_TGS);
    unsigned char msgA[LEN_MSG_A];
    unsigned char msgB[LEN_MSG_B];
    unsigned char client_ID[LEN_ID]; init_client_ID(client_ID);
    unsigned char client_address[LEN_IP]; init_client_address(client_address);
    unsigned char K_TGS[LEN_KEY]; init_K_TGS(K_TGS);

    receive_from_client(request, 24);
    printf("\n*************************************************************************\n");
    printf("    Receive :\n");
    printf("        request :");
    for (int i = 0; i < 24; ++i) {
        printf("%c", request[i]);
    }
    putchar(10);

    printf("    Send :\n");
    gene_msgA(msgA, K_Client, K_Client_TGS);
    printf("        msgA :");
    for (int i = 0; i < LEN_MSG_A; ++i) {
        printf("%02x", msgA[i]);
    }
    putchar(10);
    printf("            K_Client_TGS  :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_Client_TGS[i]);
    }
    putchar(10);
    time_t validity = time(NULL) + 86400;
    gene_msgB(msgB, client_ID, client_address, &validity, K_Client_TGS, K_TGS);
    printf("        msgB :");
    for (int i = 0; i < LEN_MSG_B; ++i) {
        printf("%02x", msgB[i]);
    }
    putchar(10);
    printf("            client_ID     :%x\n", client_ID[0]);
    printf("            client_address:%d.%d.%d.%d\n", client_address[0], client_address[1], client_address[2], client_address[2]);
    printf("            validity      :%ld - ", validity); print_time(validity);
    printf("            K_Client_TGS  :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_Client_TGS[i]);
    }
    putchar(10);
    send_to_client(msgA, LEN_MSG_A, msgB, LEN_MSG_B);
    printf("*************************************************************************\n\n");

    return 0;
}

void init_K_Client(unsigned char *K_Client) {
    K_Client[ 0] = 0x4e;
    K_Client[ 1] = 0xee;
    K_Client[ 2] = 0xbc;
    K_Client[ 3] = 0x94;
    K_Client[ 4] = 0xc0;
    K_Client[ 5] = 0x49;
    K_Client[ 6] = 0x33;
    K_Client[ 7] = 0x05;
    K_Client[ 8] = 0xaf;
}
void init_K_Client_TGS(unsigned char *K_Client_TGS) {
    K_Client_TGS[0] = 0xaf;
    K_Client_TGS[1] = 0x56;
    K_Client_TGS[2] = 0x86;
    K_Client_TGS[3] = 0x8d;
    K_Client_TGS[4] = 0xc9;
    K_Client_TGS[5] = 0x53;
    K_Client_TGS[6] = 0xe3;
    K_Client_TGS[7] = 0xf9;
}
void init_client_ID(unsigned char *client_ID) {
    client_ID[0] = 0;
}
void init_client_address(unsigned char *client_address) {
    client_address[0] = 183;
    client_address[0] = 232;
    client_address[0] = 231;
    client_address[0] = 172;
}
void init_K_TGS(unsigned char *K_TGS) {
    K_TGS[0] = 0x4e + 1;
    K_TGS[1] = 0xee + 1;
    K_TGS[2] = 0xbc + 1;
    K_TGS[3] = 0x94 + 1;
    K_TGS[4] = 0xc0 + 1;
    K_TGS[5] = 0x49 + 1;
    K_TGS[6] = 0x33 + 1;
    K_TGS[7] = 0x05 + 1;
    K_TGS[8] = 0xaf + 1;
}

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg) {
    int rfd = open("../pip/pip-as",O_RDONLY);
    if (rfd < 0) {
        ERR_EXIT("open");
    }
    size_t s = read(rfd, msg, len_msg);
    close(rfd);
    return s;
}

void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2) {
    int wfd = open("../pip/pip-client1", O_WRONLY);
    if (wfd < 0) {
        ERR_EXIT("open");
    }
    write(wfd, msg, len_msg);
    write(wfd, msg2, len_msg2);
    close(wfd);
    return ;
}

void gene_msgA(unsigned char *msgA, unsigned char *K_Client, unsigned char *K_Client_TGS) {
    encrypt(msgA, K_Client_TGS, LEN_KEY, K_Client);
}

void gene_msgB(unsigned char *msgB, unsigned char *client_ID, 
                                    unsigned char *client_address, 
                                    time_t *validity, 
                                    unsigned char *K_Client_TGS, unsigned char *K_TGS) {
    unsigned char msgB_plaintext[LEN_MSG_B];
    unsigned int len = 0;
    memcpy(msgB_plaintext + len, client_ID, LEN_ID); len += LEN_ID;
    memcpy(msgB_plaintext + len, client_address, LEN_IP); len += LEN_IP;
    memcpy(msgB_plaintext + len, (void *)validity, LEN_TIME); len += LEN_TIME;
    memcpy(msgB_plaintext + len, K_Client_TGS, LEN_KEY); len += LEN_KEY;

    encrypt(msgB, msgB_plaintext, len, K_TGS);
    return ;
}

void print_time(time_t t) {
    struct tm *lt = localtime(&t);
    char nowtime[24];
    memset(nowtime, 0, sizeof(nowtime));
    strftime(nowtime, 24, "%Y-%m-%d %H:%M:%S", lt);
    printf("%s\n", nowtime);
}