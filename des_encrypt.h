#ifndef DES_ENCRYPT_H_INCLUDED
#define DES_ENCRYPT_H_INCLUDED

extern int debug;

void des_encrypt(char * plaintext, char * writeFileName, char * key, char * iv);
void expansionPermutation(unsigned char datablock[], unsigned char Kn[], unsigned char ret[]);
void initialPermutation(unsigned char M [], unsigned char InitPermutation[]);
void createSubKeys(unsigned char key[], unsigned char K[][6]);
void des_encrypt_chunk(unsigned char key [], unsigned char M [], unsigned char ret []);

#endif
