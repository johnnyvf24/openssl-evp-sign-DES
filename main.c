/**
 * HW3 Part2 for computer security
 * Group members: John V. Flickinger, Travis Machacek
 * 
 */

#include <stdio.h>
#include "file_ops.h"
#include "rsa_utils.h"
#include "utils.h"
#include "des_encrypt.h"
int debug = 0;

int main(int argc, char **argv)
{
	int userOutKeyFile = 0, userOutFile = 0, sigOutFile = 0;
    //parse commandline arguments
    char * plaintextFile, * pKeyFile, * sessionKeyFile, * privKeyFile, * outputSessionKeyFile, * outputFile, 
		* sigOutputFile;
    int i;
    if(argc > 8) {
        for(i = 1; i < argc; i++) {
            char *arg = argv[i];
            //REQUIRED: the plaintext file
            if(strcmp(arg, "-p") == 0) {   
                i++;
                plaintextFile = argv[i];
            } 
            //REQUIRED: the third party public key
            else if(strcmp(arg, "-pubk") == 0) {
                i++;
                pKeyFile = argv[i];
            }
            //REQUIRED: the session key
            else if(strcmp(arg, "-sk") == 0) {
                i++;
                sessionKeyFile = argv[i];
            }
            //REQUIRED: the private key file
            else if(strcmp(arg, "-privk") == 0) {
                i++;
                privKeyFile = argv[i];
            } 
			//OPTIONAL: for debugging purposes
			else if(strcmp(arg, "-d") == 0) {
				debug = 1;
			} 
			//OPTIONAL: the name of the file that will contain the plaintext key
			//DEFAULT: sessionKey.key
			else if(strcmp(arg, "-kout") == 0) {
				i++;
				outputSessionKeyFile = argv[i];
				userOutKeyFile = 1;
			}
			//OPTIONAL: the name of the file to store the ciphertext
			//DEFAULT: output.bin
			else if(strcmp(arg, "-out") == 0) {
				i++;
				outputFile = argv[i];
				userOutFile = 1;
			}
			//OPTIONAL: the name of the signature file
			//DEFAULT: signature
			else if(strcmp(arg, "-sigout") == 0) {
				i++;
				sigOutputFile = argv[i];
				sigOutFile = 1;
			}
			else {
                //PRINT OUT Help message
            }
        }
        
        /*------------------------READ ALL THE FILES --------------------------*/
        char * plaintext, * pubKeyContent, * sessionKeyContent;
        //store the content of all the files
        plaintext = read_file(plaintextFile, NULL);
        pubKeyContent = read_file(pKeyFile, NULL);
        sessionKeyContent = read_file(sessionKeyFile, NULL);
		
		if(debug) {
			printf("\n\nplaintext:\n%s\n", plaintext);
			printf("\nThe size of the plaintext is %d bytes\n", (int)strlen(plaintext));
			printf("\nthird party public key:\n%s\n", pubKeyContent);
		}
		
		unsigned char decrypted[512]={}; 
		int dec_length = public_decrypt(sessionKeyContent, 512, pubKeyContent, decrypted);
		if(dec_length == -1) {
			char * error = malloc(130);;
			ERR_load_crypto_strings();
			ERR_error_string(ERR_get_error(), error);
			printf("ERROR: %s\n", error);
			free(error);
			exit(0);
		}
		
		if(debug) {
			printf("\n\nThe decrypted session key: ");
			print_array_hex(8, decrypted);
		}
		
		/*----------------------SAVE DECRYPTED SESSION KEY--------------------*/
		if(debug) {
			printf("\nWriting to file %s\n", (userOutKeyFile) ? outputSessionKeyFile:"sessionKey.key");
		}
		write_file((userOutKeyFile) ? outputSessionKeyFile:"sessionKey.key", decrypted, 8);
		
		//placeholders for the key and iv to be used for DES.
		unsigned char key [9];
		unsigned char iv [9];
		key[8] = '\0';
		iv[8] = '\0';
		
		derive_key_and_iv(decrypted, key, iv);
		
		
		/*-----------------------ENCRYPT USING DES ---------------------------*/
		if(debug) {
			printf("\nwriting ciphertext to %s\n", (userOutFile) ? outputFile:"output.bin");
		}
		
		des_encrypt(plaintext, (userOutFile) ? outputFile:"output.bin" , key, iv);
		
		
		/*-----------------------HASH AND SIGN THE CIPHERTEXT-----------------*/
		
		unsigned int dataLength;
		unsigned char * dataToSign = read_file((userOutFile) ? outputFile:"output.bin", &dataLength);
		if(debug) {
			printf("\nThe ciphertext is:\n");
			print_array_hex(strlen(dataToSign), dataToSign);
			printf("The size of the ciphertext is: %d\n", dataLength);
		}
		
		//The final part
		hash_and_sign_data(dataToSign, (sigOutFile) ? sigOutputFile:"signature", privKeyFile, dataLength);
		
    } else {
        printf("TODO: write help message");
    }

    return 0;
}
