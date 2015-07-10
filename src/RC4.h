#ifndef RC4ENC_H_
#define RC4ENC_H_

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "Base64.h"

bool RC4GenerateKeys(const unsigned char *password, int plen, unsigned char *rc4Salt, unsigned char *rc4Key);

int RC4Encrypt(char **cipher, const char *plain, int plen, const unsigned char *rc4Key);

int RC4Decrypt(unsigned char **plain, const char *cipher, int clen, const unsigned char *rc4Key);

#endif
