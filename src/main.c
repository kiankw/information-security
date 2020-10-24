#include "rsa.h"

#include <stdio.h>

void example() {
	// k = 2048 --> StrMaxLen = 245
	// StrMaxLen = k / 8 - 11
	int k = 1024;
	initKey(k);
    String *s = initstr(117);
    for (int i = 0; i < s->len; ++i) {
        s->data[i] = 'a' + i % 26;
    }
	printf("The ASCII string before encryption is:\n");
    displayStrASCII(s);
    String *afterEN = encrypt(s, k);

	putchar(10);
	printf("The hexadecimal string after encryption is:\n");
	displaystr(afterEN);
    String *afterDE = decrypt(afterEN, k);

	putchar(10);
	printf("The ASCII string after decryption is:\n");
    displayStrASCII(afterDE);

    destorystr(afterDE);
    destorystr(afterEN);
    destorystr(s);
}
void inputTest() {
	printf("Please input the length of string.\n");
	int len = 0;
	scanf("%d", &len);
	getchar();
    String *s = initstr(len);

	int k = 1024;
	while (k / 8 - 11 <= len) {
		k = k * 2;
	}
	initKey(k);
	printf("The k of RSA algorithm is %d.\n", k);

	printf("Please input the string, which should conform to ASCII encoding.\n");
	unsigned char ch = 'a';
    for (int i = 0; i < s->len; ++i) {
		scanf("%c", &ch);
        s->data[i] = (unsigned char)ch;
    }
	getchar();

	printf("The ASCII string before encryption is:\n");
    displayStrASCII(s);
    String *afterEN = encrypt(s, k);

	putchar(10);
	printf("The hexadecimal string after encryption is:\n");
	displaystr(afterEN);
    String *afterDE = decrypt(afterEN, k);

	putchar(10);
	printf("The ASCII string after decryption is:\n");
    displayStrASCII(afterDE);

    destorystr(afterDE);
    destorystr(afterEN);
    destorystr(s);
}
int main() {
	while (1) {
		printf("***********************************************\n");
		printf("Welcome to RSA algorithm system!\n");
		putchar(10);
		printf("1. Run the test example.\n");
		printf("2. Enter a new string.\n");
		printf("0. Exit system.\n");
		printf("***********************************************\n");
		int n = 0;
		scanf("%d", &n);
		getchar();
		if (n == 1) {
			example();
		} else if (n == 2) {
			inputTest();
		} else {
			break;
		}
		getchar();
	}
	printf("Goodbye!\n");
	return 0;
}

