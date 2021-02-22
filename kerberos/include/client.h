#ifndef CLIENT_H
#define CLIENT_H


#include <time.h>  // time_t

#define  AS 1
#define TGS 2
#define  SS 3

void send_to_server(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2, unsigned char server);
void receive_from_server(unsigned char *msg, unsigned int len_msg,unsigned char *msg2, unsigned int len_msg2, unsigned char server);

void init_K_Client(unsigned char *K_Client);
void init_service_ID(unsigned char *service_ID);
void init_client_ID(unsigned char *client_ID);

void analysis_msgA(unsigned char *K_Client_TGS, unsigned char *msgA, unsigned char *K_Client);

void gene_msgC(unsigned char *msgC, unsigned char *service_ID, unsigned char *msgB);
void gene_msgD(unsigned char *msgD, unsigned char *client_ID, time_t *timestamp, unsigned char *K_Client_TGS);
void analysis_msgF(unsigned char *K_CLient_SS, unsigned char *msgF, unsigned char *K_Client_TGS);

void gene_msgG(unsigned char *msgG, unsigned char *client_ID, time_t *timestamp, unsigned char *K_CLient_SS);
void analysis_msgH(unsigned char *msgH, time_t timestamp, unsigned char *K_CLient_SS);

#endif // CLIENT_H
