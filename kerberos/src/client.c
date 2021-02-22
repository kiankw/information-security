#include "../include/message.h"
#include "../include/encrypt_decrypt.h"
#include "../include/client.h"

#include <fcntl.h>  // open(), O_RDONLY
#include <stdio.h>
#include <stdlib.h>  // malloc()
#include <string.h>  // memset()
#include <sys/stat.h>  // umask(), mkfifo()
#include <unistd.h>  // read(), close()

int main() {
    umask(0);
    if (mkfifo("../pip/pip-client1",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }
    if (mkfifo("../pip/pip-client2",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }
    if (mkfifo("../pip/pip-client3",0644) < 0) {     //创建一个命名管道
        ERR_EXIT("mkfifo");
    }

    unsigned char *msgA = (unsigned char *) malloc (LEN_MSG_A * sizeof(unsigned char)); memset(msgA, 0, LEN_MSG_A);
    unsigned char *msgB = (unsigned char *) malloc (LEN_MSG_B * sizeof(unsigned char)); memset(msgB, 0, LEN_MSG_B);
    unsigned char *msgC = (unsigned char *) malloc (LEN_MSG_C * sizeof(unsigned char)); memset(msgC, 0, LEN_MSG_C);
    unsigned char *msgD = (unsigned char *) malloc (LEN_MSG_D * sizeof(unsigned char)); memset(msgD, 0, LEN_MSG_D);
    unsigned char *msgE = (unsigned char *) malloc (LEN_MSG_E * sizeof(unsigned char)); memset(msgE, 0, LEN_MSG_E);
    unsigned char *msgF = (unsigned char *) malloc (LEN_MSG_F * sizeof(unsigned char)); memset(msgF, 0, LEN_MSG_F);
    unsigned char *msgG = (unsigned char *) malloc (LEN_MSG_G * sizeof(unsigned char)); memset(msgG, 0, LEN_MSG_G);
    unsigned char *msgH = (unsigned char *) malloc (LEN_MSG_H * sizeof(unsigned char)); memset(msgH, 0, LEN_MSG_H);

    unsigned char *K_Client = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); init_K_Client(K_Client);

    unsigned char *service_ID = (unsigned char *) malloc (LEN_ID * sizeof(unsigned char)); init_service_ID(service_ID);
    unsigned char  *client_ID = (unsigned char *) malloc (LEN_ID * sizeof(unsigned char)); init_client_ID ( client_ID);
    unsigned char *K_Client_TGS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); memset(K_Client_TGS, 0, LEN_KEY);
    unsigned char *K_CLient_SS = (unsigned char *) malloc (LEN_KEY * sizeof(unsigned char)); memset(K_CLient_SS, 0, LEN_KEY);



    printf("\n*************************************************************************\n");
    printf("Communicate with AS\n");
    unsigned char request[24] = "User Bob request serve!";
    request[23] = '\0';
    int len_request = 24;
    printf("    Send :\n        ");
    send_to_server(request, len_request, NULL, 0, AS);
    for (int i = 0; i < len_request; ++i) {
        printf("%c", request[i]);
    }
    putchar(10);

    receive_from_server(msgA, LEN_MSG_A, msgB, LEN_MSG_B, AS); 
    printf("    Receive :\n");
    printf("        msgA :");
    for (int i = 0; i < LEN_MSG_A; ++i) {
        printf("%02x", msgA[i]);
    }
    putchar(10);
    analysis_msgA(K_Client_TGS, msgA, K_Client);
    printf("        msgB :");
    for (int i = 0; i < LEN_MSG_B; ++i) {
        printf("%02x", msgB[i]);
    }
    putchar(10);

    
    printf("*************************************************************************\n\n");

    printf("\n*************************************************************************\n");
    printf("Communicate with TGS\n");
    printf("    Send :\n");
    gene_msgC(msgC, service_ID, msgB);
    printf("        msgC :");
    for (int i = 0; i < LEN_MSG_C; ++i) {
        printf("%02x", msgC[i]);
    }
    putchar(10);

    time_t timestamp = time(NULL);
    gene_msgD(msgD, client_ID, &timestamp, K_Client_TGS);
    printf("        msgD :");
    for (int i = 0; i < LEN_MSG_D; ++i) {
        printf("%02x", msgD[i]);
    }
    putchar(10);
    send_to_server(msgC, LEN_MSG_C, msgD, LEN_MSG_D, TGS);

    printf("    Receive :\n");
    receive_from_server(msgE, LEN_MSG_E, msgF, LEN_MSG_F, TGS);
    printf("        msgE :");
    for (int i = 0; i < LEN_MSG_E; ++i) {
        printf("%02x", msgE[i]);
    }
    putchar(10);
    printf("        msgF :");
    for (int i = 0; i < LEN_MSG_F; ++i) {
        printf("%02x", msgF[i]);
    }
    putchar(10);

    analysis_msgF(K_CLient_SS, msgF, K_Client_TGS);
    printf("*************************************************************************\n\n");

    printf("\n*************************************************************************\n");
    printf("Communicate with SS\n");
    gene_msgG(msgG, client_ID, &timestamp, K_CLient_SS);

    printf("    Send :\n");
    printf("        msgG :");
    for (int i = 0; i < LEN_MSG_G; ++i) {
        printf("%02x", msgG[i]);
    }
    putchar(10);
    send_to_server(msgE, LEN_MSG_E, msgG, LEN_MSG_G, SS);

    printf("    Receive :\n");
    receive_from_server(msgH, LEN_MSG_H, NULL, 0, SS);
    printf("        msgH :");
    for (int i = 0; i < LEN_MSG_H; ++i) {
        printf("%02x", msgH[i]);
    }
    putchar(10);

    analysis_msgH(msgH, timestamp, K_CLient_SS);
    printf("*************************************************************************\n\n");

    free(K_CLient_SS);
    free(client_ID);
    free(service_ID);
    free(K_Client_TGS);
    free(K_Client);
    free(msgH);
    free(msgG);
    free(msgF);
    free(msgE);
    free(msgD);
    free(msgC);
    free(msgB);
    free(msgA);
    return 0;
}

void send_to_server(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2, unsigned char server) {
    int wfd = -1;
    switch (server) {
    case AS:
        wfd = open("../pip/pip-as", O_WRONLY);
        break;
    case TGS:
        wfd = open("../pip/pip-tgs", O_WRONLY);
        break;
    case SS:
        wfd = open("../pip/pip-ss", O_WRONLY);
        break;
    }
    if (wfd < 0) {
        ERR_EXIT("open pip");
    }
    write(wfd, msg, len_msg);
    if (len_msg2) write(wfd, msg2, len_msg2);
    close(wfd);
    return ;
}
void receive_from_server(unsigned char *msg, unsigned int len_msg,unsigned char *msg2, unsigned int len_msg2, unsigned char server) {
    int rfd = -1;
    switch (server) {
    case AS:
        rfd = open("../pip/pip-client1", O_RDONLY);
        break;
    case TGS:
        rfd = open("../pip/pip-client2", O_RDONLY);
        break;
    case SS:
        rfd = open("../pip/pip-client3", O_RDONLY);
        break;
    }
    if (rfd < 0) {
        ERR_EXIT("open pip");
    }
    read(rfd, msg, len_msg);
    if (len_msg2) read(rfd, msg2, len_msg2);
    close(rfd);
    return ;
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

void init_service_ID(unsigned char *service_ID) {
    service_ID[0] = 2;
}

void init_client_ID(unsigned char *client_ID) {
    client_ID[0] = 1;
}

void analysis_msgA(unsigned char *K_Client_TGS, unsigned char *msgA, unsigned char *K_Client) {
    unsigned char *msgA_plaintext = (unsigned char *) malloc (LEN_MSG_A * sizeof(unsigned char)); memset(msgA_plaintext, 0, LEN_MSG_A);
    decrypt(msgA_plaintext, msgA, LEN_MSG_A, K_Client);
    memcpy(K_Client_TGS, msgA_plaintext, LEN_KEY);
    printf("            K_Client_TGS :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", msgA_plaintext[i]);
    }
    putchar(10);
}

void gene_msgC(unsigned char *msgC, unsigned char *service_ID, unsigned char *msgB) {
    memcpy(msgC, service_ID, LEN_ID);
    memcpy(msgC + LEN_ID, msgB, LEN_MSG_B);
}

void gene_msgD(unsigned char *msgD, unsigned char *client_ID, time_t *timestamp, unsigned char *K_Client_TGS) {
    unsigned char msgD_plaintext[LEN_MSG_D];
    unsigned int len = 0;
    memcpy(msgD_plaintext + len, client_ID, LEN_ID); len += LEN_ID;
    memcpy(msgD_plaintext + len, (void *)timestamp, LEN_TIME); len += LEN_TIME;
    encrypt(msgD, msgD_plaintext, LEN_MSG_D, K_Client_TGS);
    return ;
}

void analysis_msgF(unsigned char *K_CLient_SS, unsigned char *msgF, unsigned char *K_Client_TGS) {
    printf("    Analysis :\n");
    unsigned char *msgF_plaintext = (unsigned char *) malloc (LEN_MSG_F * sizeof(unsigned char)); memset(msgF_plaintext, 0, LEN_MSG_F);
    memset(msgF_plaintext, 0, LEN_MSG_F);
    decrypt(msgF_plaintext, msgF, LEN_MSG_F, K_Client_TGS);
    memcpy(K_CLient_SS, msgF_plaintext, LEN_KEY);
    printf("        K_CLient_SS :");
    for (int i = 0; i < LEN_KEY; ++i) {
        printf("%02x", K_CLient_SS[i]);
    }
    putchar(10);
    free(msgF_plaintext);
    return ;
}

void gene_msgG(unsigned char *msgG, unsigned char *client_ID, time_t *timestamp, unsigned char *K_CLient_SS) {
    unsigned char *msgG_plaintext = (unsigned char *) malloc (LEN_MSG_G * sizeof(unsigned char)); memset(msgG_plaintext, 0, LEN_MSG_G);
    int len_msgG_plaintext = 0;
    memcpy(msgG_plaintext + len_msgG_plaintext, client_ID, LEN_ID); len_msgG_plaintext += LEN_ID;
    memcpy(msgG_plaintext + len_msgG_plaintext, (void *)timestamp, LEN_TIME); len_msgG_plaintext += LEN_TIME;
    encrypt(msgG, msgG_plaintext, len_msgG_plaintext, K_CLient_SS);
    free(msgG_plaintext);
    return ;
}

void analysis_msgH(unsigned char *msgH, time_t timestamp, unsigned char *K_CLient_SS) {
    printf("    Analysis :\n");
    time_t timestamp_from_SS = -1;
    unsigned char *msgH_plaintext = (unsigned char *) malloc (LEN_MSG_H * sizeof(unsigned char)); memset(msgH_plaintext, 0, LEN_MSG_H);
    decrypt(msgH_plaintext, msgH, LEN_MSG_H, K_CLient_SS);
    memcpy((void *)&timestamp_from_SS, msgH_plaintext + LEN_ID, LEN_TIME);
    printf("        timestamp_from_SS %ld\n", timestamp_from_SS);
    if (timestamp_from_SS - timestamp == 1) {
        printf("\nAuthentication is successful!\n\n");
    }
    free(msgH_plaintext);
    return ;
}