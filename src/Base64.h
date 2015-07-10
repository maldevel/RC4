#ifndef BASE64_H_
#define BASE64_H_

#include <windows.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

int Base64Encode(char **dest, const char *src, unsigned int slen);
int Base64Decode(char **dest, const char *src);
unsigned int countDecodedLength(const char *encoded);


#endif
