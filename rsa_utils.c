#include "rsa_utils.h"
#include <stdio.h>

int padding = RSA_NO_PADDING;	//Didn't know exactly how to pad, so no padding was used

//Initialize openssl RSA.
RSA * initRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
 
    return rsa;
}

/**
 * @brief decrypt and get the session key from a third party public key.
 * @param enc_data, the encrypted data
 * @param data_len, the length of the encrypted data
 * @param key, the public key
 * @param decrypted, the decrypted output
 * @return the length of the decryption or -1 if it was a failure.
 */
int public_decrypt(unsigned char * enc_data, int length_of_data, unsigned char * pubKey, unsigned char *decrypted)
{
    RSA * rsa = initRSA(pubKey,1);
    return RSA_public_decrypt(length_of_data, enc_data, decrypted, rsa, padding);
}

void hash_and_sign_data(unsigned char * data, char * signatureOutputFileName, char * privKeyFileName) {
	OpenSSL_add_all_algorithms();
	
	//how much data are we hashing?
	int sizeOfData= strlen(data);
	
	if(debug) {
		printf("We are hashing %d bytes of data\n", sizeOfData);
	}
	
	unsigned char outHash [32 +1];
	outHash[sizeOfData] = '\0';
	
	unsigned int md_len = -1;
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if(NULL != md) {
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, data, sizeOfData);
        EVP_DigestFinal_ex(&mdctx, outHash, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
    }
	
	if(debug) {
		printf("The hash of the file is: ");
		print_array_hex(32, outHash);
	}
	
	EVP_PKEY_CTX *ctx;
	unsigned char *sig;
	size_t mdlen = 32, siglen;
	EVP_PKEY *signing_key;
	
	FILE *fp = fopen(privKeyFileName, "r");
	PEM_read_PrivateKey(fp, &signing_key, NULL, NULL);
	
	ctx = EVP_PKEY_CTX_new(signing_key, NULL /* no engine */);
	
	if(!ctx) printf("An error occurred while signing");
	if (EVP_PKEY_sign_init(ctx) <= 0) printf("An error occurred while signing");
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) printf("An error occurred while signature padding");
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) printf("An error occurred while signing");
		
	/*Determine buffer length*/
	if (EVP_PKEY_sign(ctx, NULL, &siglen, outHash, mdlen) <= 0)
        printf("ERROR");

	sig = OPENSSL_malloc(siglen);

	if (!sig)
		printf("ERROR");

	if (EVP_PKEY_sign(ctx, sig, &siglen, outHash, mdlen) <= 0)
		printf("ERROR");

	/* Signature is siglen bytes written to buffer sig */
	if(debug) {
		printf("The signature is: \n");
		print_array_hex(siglen, sig);
	}
}

/**
 * @brief Derive the key and initialization vector from the session key.The key is the first 8 bytes from
 * a SHA256 hash of the sessionKey, the IV is the second 8 bytes.
 * @param session_key, only the first 8 bytes will be used.
 * @param key, the key outputted. 
 * @param iv, the initialization vector outputted.
 */
void derive_key_and_iv(unsigned char * sessionKey, unsigned char * key, unsigned char * iv) {
	OpenSSL_add_all_algorithms();
	
	unsigned char * sKey[8];
	unsigned char outHash [33];
	memcpy(sKey, sessionKey, 8);
	if(debug) print_array_hex(8, sKey);
	
	unsigned int md_len = -1;
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    if(NULL != md) {
        EVP_MD_CTX mdctx;
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, sKey, 8);
        EVP_DigestFinal_ex(&mdctx, outHash, &md_len);
        EVP_MD_CTX_cleanup(&mdctx);
    }
	
	if(debug) {
		printf("The outputted hash is: ");
		print_array_hex(32, outHash);
	}
	
	//Use the first 8 bytes as the key
	memcpy(key, outHash, 8);
	if(debug) {
		printf("\nThe symmetric key is ");
		print_array_hex(8, key);
	}
	
	//Use the second 8 bytes as the iv
	memcpy(iv, outHash + 8, 8);
	if(debug) {
		printf("\nThe iv is ");
		print_array_hex(8, iv);
	}
}
