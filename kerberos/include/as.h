#ifndef AS_H
#define AS_H


#include <time.h> // time_t

void init_K_Client(unsigned char *K_Client);
void init_K_Client_TGS(unsigned char *K_Client_TGS);
void init_client_ID(unsigned char *client_ID);
void init_client_address(unsigned char *client_address);
void init_K_TGS(unsigned char *K_TGS);

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg);
void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2);

void gene_msgA(unsigned char *msgA, unsigned char *K_Client, unsigned char *K_Client_TGS);
void gene_msgB(unsigned char *msgB, unsigned char *client_ID, 
                                    unsigned char *client_address, 
                                    time_t *validity, 
                                    unsigned char *K_Client_TGS, unsigned char *K_TGS);

void print_time(time_t t);

#endif // AS_H
