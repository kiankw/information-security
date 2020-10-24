#ifndef RSA_H
#define RSA_H

#include "key.h"
#include "int_and_str.h"

String * encrypt(const String *M, const int k);
String * decrypt(const String *C, const int k);

#endif // RSA_H
