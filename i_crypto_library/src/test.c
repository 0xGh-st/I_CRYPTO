#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

void hexdump(const char* title, void* mem, unsigned int len){
	unsigned int i = 0;
	unsigned int j = 0;
	fprintf(stdout, "-[%s](%d)\n", title, len);
	for (i = 0; i < len + ((len % 16) ? (16 - len % 16) : 0); i++){
		// print offset
		if (i % 16 == 0)
			printf("0x%08X: ", i);
		// print hex data
		if (i < len)
			printf("%02X ", 0xFF & ((char*)mem)[i]);
		else
			printf("   ");
		// print ascii dump
		if (i % 16 == (16 - 1)){
			for (j = i - (16 - 1); j <= i; j++){
				if (j >= len)
					putchar(' ');
				else if ((((char*)mem)[j] >= 32) && (((char*)mem)[j] <= 126))
					putchar(0xFF & ((char*)mem)[j]);
				else
					putchar('.');
			}
			putchar('\n');
		}
	}  // for
	puts("");
}

int main(){
	unsigned char data[16] = "test text sample";
	unsigned int datalength = 16;

	unsigned char key[16] = {0x00, };
	unsigned int keylength = 16;
	
	unsigned char output[33] = {0x00, };
	unsigned int outputlength = 0;

	unsigned char decData[32] = {0x00, };
	unsigned int decDatalength = 0;

	AES_KEY stKey;
	memset(&stKey, 0, sizeof(AES_KEY));

	hexdump("data", data, 20);

	AES_set_encrypt_key(key, 128, &stKey);
	AES_ecb_encrypt(data, output, &stKey, AES_ENCRYPT);

	hexdump("enc", output, 32);

	//memset(&stKey, 0, sizeof(AES_KEY));

	//AES_set_decrypt_key(key, 128, &stKey);

	AES_ecb_encrypt(output, decData, &stKey, AES_ENCRYPT);

	hexdump("dec", decData, 32);
	
	//printf("dec : %s\n", decData);
}
