#include "../include/encrypt_decrypt.h"
#include "../include/tgs.h"
#include "../include/message.h"

#include <fcntl.h>  // open(), O_RDONLY
#include <stdio.h>
#include <stdlib.h>  // malloc()
#include <string.h>  // memset()
#include <sys/stat.h>  // umask(), mkfifo()
#include <unistd.h>  // read(), close()

int main() {
    umask(0);
    if (mkfifo("../pip/pip-tgs",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }
    printf("This is TGS!\n");
    printf("Please waiting...\n");

    unsigned char *msgB = (unsigned char *) malloc (LEN_MSG_B * sizeof(unsigned char)); memset(msgB, 0, LEN_MSG_B);
    unsigned char *msgC = (unsigned char *) malloc (LEN_MSG_C * sizeof(unsigned char)); memset(msgC, 0, LEN_MSG_C);
    unsigned char *msgD = (unsigned char *) malloc (LEN_MSG_D * sizeof(unsigned char)); memset(msgD, 0, LEN_MSG_D);
    unsigned char *msgE = (unsigned char *) malloc (LEN_MSG_E * sizeof(unsigned char)); memset(msgE, 0, LEN_MSG_E);
    unsigned char *msgF = (unsigned char *) malloc (LEN_MSG_F * sizeof(unsigned char)); memset(msgF, 0, LEN_MSG_F);

    unsigned char *K_Client_TGS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); memset(K_Client_TGS, 0, LEN_KEY);
    unsigned char *K_TGS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); init_K_TGS(K_TGS);
    unsigned char *K_SS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); init_K_SS(K_SS);
    unsigned char *K_Client_SS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); init_K_Client_SS(K_Client_SS);

    unsigned char *service_ID = (unsigned char *) malloc (LEN_ID * sizeof(unsigned char)); memset(service_ID, 0, LEN_ID);
    unsigned char *client_ID_from_D = (unsigned char *) malloc (LEN_ID * sizeof(unsigned char)); memset(client_ID_from_D, 0, LEN_ID);

    unsigned char *client_address = (unsigned char *) malloc (LEN_IP * sizeof(unsigned char)); memset(client_address, 0, LEN_IP);

    time_t validity = -1;

    receive_from_client(msgC, LEN_MSG_C, msgD, LEN_MSG_D);
    printf("\n*************************************************************************\n");
    printf("    Receive :\n");
    printf("        msgC :");
    for (int i = 0; i < LEN_MSG_C; ++i) {
        printf("%02x", msgC[i]);
    }
    putchar(10);
    analysis_msgC(service_ID, msgB, msgC);
    analysis_msgB(client_address, &validity, K_Client_TGS, msgB, K_TGS);
    printf("            service_ID    :%x\n", service_ID[0]);
    printf("            client_address:%d.%d.%d.%d\n", client_address[0], client_address[1], client_address[2], client_address[2]);
    printf("            validity      :%ld\n", validity);
    printf("            K_Client_TGS  :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_Client_TGS[i]);
    }
    putchar(10);

    printf("        msgD :");
    for (int i = 0; i < LEN_MSG_D; ++i) {
        printf("%02x", msgD[i]);
    }
    putchar(10);
    analysis_msgD(client_ID_from_D, msgD, K_Client_TGS);


    printf("    Send :\n");
    gene_msgE(msgE, service_ID, client_ID_from_D, client_address, &validity, K_Client_SS, K_SS);
    printf("        msgE :");
    for (int i = 0; i < LEN_MSG_E; ++i) {
        printf("%02x", msgE[i]);
    }
    putchar(10);
    printf("            service_ID    :%x\n", service_ID[0]);
    printf("            client_ID     :%x\n", client_ID_from_D[0]);
    printf("            client_address:%d.%d.%d.%d\n", client_address[0], client_address[1], client_address[2], client_address[2]);
    printf("            validity      :%ld\n", validity);
    printf("            K_Client_SS   :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_Client_SS[i]);
    }
    putchar(10);

    gene_msgF(msgF, K_Client_SS, K_Client_TGS);
    printf("        msgF :");
    for (int i = 0; i < LEN_MSG_F; ++i) {
        printf("%02x", msgF[i]);
    }
    putchar(10);
    printf("            K_Client_SS   :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_Client_SS[i]);
    }
    putchar(10);

    send_to_client(msgE, LEN_MSG_E, msgF, LEN_MSG_F);
    printf("*************************************************************************\n\n");
    
    free(client_address);
    free(client_ID_from_D);
    free(service_ID);
    free(K_Client_SS);
    free(K_SS);
    free(K_TGS);
    free(K_Client_TGS);
    free(msgF);
    free(msgE);
    free(msgD);
    free(msgC);
    free(msgB);
    return 0;
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

void init_K_Client_SS(unsigned char *K_Client_SS) {
    K_Client_SS[0] = 0x4e + 4;
    K_Client_SS[1] = 0xee + 4;
    K_Client_SS[2] = 0xbc + 4;
    K_Client_SS[3] = 0x94 + 4;
    K_Client_SS[4] = 0xc0 + 4;
    K_Client_SS[5] = 0x49 + 4;
    K_Client_SS[6] = 0x33 + 4;
    K_Client_SS[7] = 0x05 + 4;
    K_Client_SS[8] = 0xaf + 4;
}

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2) {
    int rfd = open("../pip/pip-tgs",O_RDONLY);
    if (rfd < 0) {
        ERR_EXIT("open");
    }
    read(rfd, msg, len_msg);
    if (len_msg2) read(rfd, msg2, len_msg2);
    close(rfd);
    return 0;
}
void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2) {
    int wfd = open("../pip/pip-client2", O_WRONLY);
    if (wfd < 0) {
        ERR_EXIT("open");
    }
    write(wfd, msg, len_msg);
    if (len_msg2) write(wfd, msg2, len_msg2);
    close(wfd);
    return ;
}

void analysis_msgC(unsigned char *service_ID, unsigned char *msgB, unsigned char *msgC) {
    memcpy(service_ID, msgC, LEN_ID);
    memcpy(msgB, msgC + LEN_ID, LEN_MSG_B);
}

void analysis_msgB(unsigned char *client_address, time_t *validity, unsigned char *K_Client_TGS, unsigned char *msgB, unsigned char *K_TGS) {
    unsigned char *msgB_plaintext = (unsigned char *) malloc (LEN_MSG_B * sizeof(unsigned char)); memset(msgB_plaintext, 0, LEN_MSG_B);
    decrypt(msgB_plaintext, msgB, LEN_MSG_B, K_TGS);

    memcpy(client_address, msgB_plaintext + LEN_ID, LEN_IP);
    memcpy((void *)validity, msgB_plaintext + LEN_ID + LEN_IP, LEN_TIME);
    memcpy(K_Client_TGS, msgB_plaintext + LEN_ID + LEN_IP + LEN_TIME, LEN_KEY);
    free(msgB_plaintext);
}

void analysis_msgD(unsigned char *client_ID_from_D, unsigned char *msgD, unsigned char *K_Client_TGS) {
    unsigned char *msgD_plaintext = (unsigned char *) malloc (LEN_MSG_D * sizeof(unsigned char)); 
    memset(msgD_plaintext, 0, LEN_MSG_D);
    decrypt(msgD_plaintext, msgD, LEN_MSG_D, K_Client_TGS);
    memcpy(client_ID_from_D, msgD_plaintext, LEN_ID);
    free(msgD_plaintext);
}

void gene_msgE(unsigned char *msgE, unsigned char *service_ID, unsigned char *client_ID, unsigned char *client_net_address, time_t *validity, unsigned char *K_Client_SS, unsigned char *K_SS) {
    int len_ST = 24;
    unsigned char *ST_plaintext = (unsigned char *) malloc (len_ST * sizeof(unsigned char)); memset(ST_plaintext, 0, len_ST);
    
    int len_ST_plaintext = 0;
    memcpy(ST_plaintext + len_ST_plaintext, client_ID, LEN_ID); len_ST_plaintext += LEN_ID;
    memcpy(ST_plaintext + len_ST_plaintext, client_net_address, LEN_IP); len_ST_plaintext += LEN_IP;
    memcpy(ST_plaintext + len_ST_plaintext, (void *)validity, LEN_TIME); len_ST_plaintext += LEN_TIME;
    memcpy(ST_plaintext + len_ST_plaintext, K_Client_SS, LEN_KEY); len_ST_plaintext += LEN_KEY;

    unsigned char *ST = (unsigned char *) malloc (len_ST * sizeof(unsigned char)); memset(ST, 0, len_ST);
    encrypt(ST, ST_plaintext, len_ST_plaintext, K_SS);
#if 0
    printf("ST :");
    for (int i = 0; i < len_ST; ++i) {
        printf("%02x", ST[i]);
    }
    putchar(10);
#endif

    memcpy(msgE, service_ID, LEN_ID);
    memcpy(msgE + LEN_ID, ST, len_ST);

    free(ST);
    free(ST_plaintext);
    return ;
}

void gene_msgF(unsigned char *msgF, unsigned char *K_Client_SS, unsigned char *K_Client_TGS) {
    encrypt(msgF, K_Client_SS, LEN_KEY, K_Client_TGS);
}
