#ifndef SS_H
#define SS_H


#include <time.h>  // time_t

void init_K_SS(unsigned char *K_SS);

unsigned int receive_from_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2);
void send_to_client(unsigned char *msg, unsigned int len_msg, unsigned char *msg2, unsigned int len_msg2);

void analysis_msgE(unsigned char *K_CLient_SS, unsigned char *msgE, unsigned char *K_SS);
void analysis_msgG(unsigned char *client_ID, time_t *timestamp, unsigned char *msgG, unsigned char *K_CLient_SS);
void gene_msgH(unsigned char *msgH, unsigned char *client_ID, time_t *timestamp , unsigned char *K_CLient_SS);

#endif // SS_H
