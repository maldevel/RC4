#include "RC4.h"


bool GenerateKeys(const unsigned char *password, int plen, unsigned char *rc4Salt, unsigned char *rc4Key){
	if (password == NULL || plen <= 0) return false;

	if (RAND_bytes(rc4Salt, SALT_LEN) == 0) return false;
	rc4Salt[SALT_LEN] = '\0';

	if (PKCS5_PBKDF2_HMAC_SHA1(password, RC4_KEY_LEN, rc4Salt, SALT_LEN, ITERATIONS, RC4_KEY_LEN, rc4Key) == 0) 
		return false;

	rc4Key[RC4_KEY_LEN] = '\0';

	return true;
}

int Encrypt(char **cipher, const char *plain, int plen, const unsigned char *rc4Key){
	if (plain == NULL || plen <= 0 || rc4Key == NULL) return 0;

	EVP_CIPHER_CTX *ctx;
	unsigned char rc4IV[EVP_MAX_IV_LENGTH + 1] = { 0 }; //remains empty
	unsigned char *cipher_tmp = { 0 };
	int len = 0, cipherTextLen = 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) return 0;

	if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, rc4Key, rc4IV)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	cipher_tmp = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plen);
	if (cipher_tmp == NULL) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		return 0;
	}

	if (1 != EVP_EncryptUpdate(ctx, cipher_tmp, &len, (unsigned char *)plain, plen - 1)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen = len;

	if (1 != EVP_EncryptFinal_ex(ctx, cipher_tmp + len, &len)) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipherTextLen += len;

	if (ctx) EVP_CIPHER_CTX_free(ctx);

	if (cipherTextLen <= 0) {
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	cipher_tmp[cipherTextLen] = '\0';

	if ((cipherTextLen = Base64Encode(cipher, cipher_tmp, cipherTextLen + 1)) <= 0){
		if (cipher_tmp) {
			HeapFree(GetProcessHeap(), 0, cipher_tmp);
			cipher_tmp = NULL;
		}
		return 0;
	}

	if (cipher_tmp) {
		HeapFree(GetProcessHeap(), 0, cipher_tmp);
		cipher_tmp = NULL;
	}

	return cipherTextLen;
}

int Decrypt(unsigned char **plain, const char *cipher, int clen, const unsigned char *rc4Key){
	if (cipher == NULL || clen <= 0 || rc4Key == NULL) return 0;

	EVP_CIPHER_CTX *ctx;
	int len = 0, plainTextLen = 0, decodedLen = 0, converted_bytes = 0, retValue = 0;
	unsigned char *plain_tmp = { 0 };
	unsigned char rc4IV[EVP_MAX_IV_LENGTH + 1] = { 0 }; //remains empty

	if ((decodedLen = Base64Decode(&plain_tmp, cipher)) == 0) return 0;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	if (1 != EVP_DecryptInit_ex(ctx, EVP_rc4(), NULL, rc4Key, rc4IV)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	*plain = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decodedLen);
	if (*plain == NULL) {
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		return 0;
	}

	if (1 != EVP_DecryptUpdate(ctx, *plain, &len, plain_tmp, decodedLen - 1)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain_tmp) {
			HeapFree(GetProcessHeap(), 0, plain_tmp);
			plain_tmp = NULL;
		}
		if (plain) {
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	if (plain_tmp) {
		HeapFree(GetProcessHeap(), 0, plain_tmp);
		plain_tmp = NULL;
	}

	plainTextLen = len;

	if (1 != EVP_DecryptFinal_ex(ctx, *plain + len, &len)){
		if (ctx) EVP_CIPHER_CTX_free(ctx);
		if (plain) {
			HeapFree(GetProcessHeap(), 0, plain);
			plain = NULL;
		}
		return 0;
	}

	plainTextLen += len;
	retValue = plainTextLen;

	*(*plain + plainTextLen) = '\0';

	if (ctx) EVP_CIPHER_CTX_free(ctx);

	return retValue;
}
