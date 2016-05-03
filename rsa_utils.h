#ifndef RSA_UTILS_H_INCLUDED
#define RSA_UTILS_H_INCLUDED

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

extern int debug;

RSA * initRSA(unsigned char * key,int public);
void hash_and_sign_data(unsigned char * data, char * signatureOutputFileName, char * privKeyFileName);
int public_decrypt(unsigned char * enc_data,int data_len, unsigned char * key, unsigned char *decrypted);
void derive_key_and_iv(unsigned char * sessionKey, unsigned char * key, unsigned char * iv);

#endif