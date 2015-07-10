#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#include "RC4.h"

int main(void){
	const unsigned char *password = "TESTING_PASS_TESTING_PASS_TESTING_PASS_TESTING_PASS\0";
	unsigned char rc4Salt[PKCS5_SALT_LEN + 1] = { 0 };
	unsigned char rc4Key[RC4_KEY_LEN + 1] = { 0 };

	const char plain[] = "PLAIN_TEXT_PLAIN_TEXT_PLAIN_TEXT\0";
	int cipherTextLength = 0;
	char *ciphertext = { 0 };
	char *decryptedtext = { 0 };

	if (GenerateKeys(password, strlen(password) + 1, rc4Salt, rc4Key)){
		cipherTextLength = Encrypt(&ciphertext, plain, strlen(plain) + 1, rc4Key);
		if (cipherTextLength > 0){
			printf("Encrypted text: %s\n\n", ciphertext);

			if (Decrypt(&decryptedtext, ciphertext, cipherTextLength, rc4Key) > 0){
				printf("Decrypted text: %s\n\n", decryptedtext);

				if (decryptedtext){
					HeapFree(GetProcessHeap(), 0, decryptedtext);
					decryptedtext = NULL;
				}
			}

			if (ciphertext){
				HeapFree(GetProcessHeap(), 0, ciphertext);
				ciphertext = NULL;
			}
		}
	}

	return EXIT_SUCCESS;
}
