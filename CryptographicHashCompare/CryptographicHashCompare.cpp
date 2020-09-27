#include <stdio.h>
#include <string.h>
#include "openssl/sha.h"

// Taken from https://stackoverflow.com/a/919375/12586927
int main()
{
	unsigned char ibuf[] = "password";
	unsigned char obuf[20];
	
	SHA1(ibuf, strlen((char*)ibuf), obuf);	
	
	int i;
	for (i = 0; i < sizeof(obuf); i++) {
		printf("%02x ", obuf[i]);
	}
	printf("\n");

	return 0;
}


