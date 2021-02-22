#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdio.h>

#define ERR_EXIT(m) do {\
    perror(m);\
    exit(EXIT_FAILURE);} while(0)

#define LEN_KEY 8
#define LEN_IP 4
#define LEN_ID 1
#define LEN_TIME 8

#define LEN_MSG_A 16
#define LEN_MSG_B 24
#define LEN_MSG_C 25
#define LEN_MSG_D 16
#define LEN_MSG_E 25
#define LEN_MSG_F 16
#define LEN_MSG_G 16
#define LEN_MSG_H 16

#endif // MESSAGE_H
