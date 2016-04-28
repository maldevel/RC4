#ifndef RC4ENC_H_
#define RC4ENC_H_

#define ITERATIONS		10000
#define RC4_KEY_LEN		16
#define SALT_LEN		16

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "Base64.h"

bool GenerateKeys(const unsigned char *password, int plen, unsigned char *rc4Salt, unsigned char *rc4Key);

int Encrypt(char **cipher, const char *plain, int plen, const unsigned char *rc4Key);

int Decrypt(unsigned char **plain, const char *cipher, int clen, const unsigned char *rc4Key);

#endif
