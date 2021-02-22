#ifndef CLIENT_H
#define CLIENT_H


#include <time.h> // time_t

void init_K_TGS(unsigned char *K_TGS);
void init_K_SS(unsigned char *K_SS);
void init_K_Client_SS(unsigned char *K_Client_SS);

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2);
void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2);

void analysis_msgC(unsigned char *service_ID, unsigned char *msgB, unsigned char *msgC);
void analysis_msgB(unsigned char *client_address, time_t *validity, unsigned char *K_Client_TGS, unsigned char *msgB, unsigned char *K_TGS);
void analysis_msgD(unsigned char *client_ID_from_D, unsigned char *msgD, unsigned char *K_Client_TGS);
void gene_msgE(unsigned char *msgE, unsigned char *service_ID, unsigned char *client_ID, unsigned char *client_net_address, time_t *validity, unsigned char *K_Client_SS, unsigned char *K_SS);
void gene_msgF(unsigned char *msgF, unsigned char *K_Client_SS, unsigned char *K_Client_TGS);

void print_time(time_t t);

#endif // CLIENT_H
