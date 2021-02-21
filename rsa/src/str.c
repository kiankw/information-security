#include "str.h"

#include <stdio.h>
#include <stdlib.h>

/* Alloc space for the String and initialize */
String *initstr (int len_) {
    String *str = (String *) malloc (sizeof (String));
    str->data = (unsigned char *) malloc (len_ * sizeof (unsigned char));
    str->len = len_;
    return str;
}

/* 
Connect the src string to the end of the dest string,
Return the pointer to the dest string
*/
String * catstr(String *dest, const String *src) {
    if (src == NULL)
        return dest;
    if (dest == NULL) {
        int lens = src->len;
        dest = initstr(lens);
        for (int i = 0; i < lens; ++i) {
            dest->data[i] = src->data[i];
        }
    } else {
        int lend = dest->len;
		int lens = src->len;
        dest->data = (unsigned char *) realloc(dest->data, (lend + lens) * sizeof (unsigned char));
        for (int i = 0; i < lens; ++i) {
            dest->data[lend + i] = src->data[i];
        }
        dest->len = lend + lens;
    }
    return dest;
}

/* Prints each character of the string in hex */
void displaystr(const String *str) {
    if (str == NULL)
        return ;
    for (int i = 0; i < str->len; ++i) {
        printf("%02X", str->data[i]);
    }
    putchar(10);
}

/* Prints each character of the string in ASCII encoding */
void displayStrASCII(const String *str) {
	if (str == NULL)
        return ;
    for (int i = 0; i < str->len; ++i) {
        printf("%c", str->data[i]);
    }
    putchar(10);
}

/* Returns the length of the string */
int lenstr(const String *str) {
    if (str == NULL)
        return -1;
    return str->len;
}

/* Destroy string, free alloced space */
void destorystr(String *str) {
    if (str == NULL)
        return ;
    str->len = 0;
    free(str->data);
    free(str);
}
