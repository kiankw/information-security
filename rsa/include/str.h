#ifndef STR_H
#define STR_H

/* Each char represents a octot */
typedef struct String_ {
    unsigned char *data;
    int len;
} String;

/* Alloc space for the String and initialize */
String *initstr (int len_);

/* 
Connect the src string to the end of the dest string,
Return the pointer to the dest string
*/
String * catstr(String *dest, const String *src);

/* Returns the length of the string */
int lenstr(const String *str);

/* Prints each character of the string in hex */
void displaystr(const String *str);

/* Prints each character of the string in ASCII encoding */
void displayStrASCII(const String *str);

/* Destroy string, free alloced space */
void destorystr(String *str);

#endif // STR_H
