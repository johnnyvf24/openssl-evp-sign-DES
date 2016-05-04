/**
 * DES, John F. and Travis M.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */
#include "des_encrypt.h"

/**
 * @brief Encrypt in CBC mode.
 * @param plaintext
 * @param writeFileName
 * @param key
 * @param iv
 */

void des_encrypt(char * plaintext, char * writeFileName, char * key, char * iv) {
	int plaintextSize = strlen(plaintext);

	//find out how many blocks we are working with
	int numBlocks = plaintextSize/8 + ((plaintextSize % 8) ? 1:0);
	printf("NUMBLOCKS: %d\n",numBlocks);
	FILE * output_file = fopen(writeFileName, "w");
	if (output_file == NULL) {
		printf("Could not open %s to write data.", writeFileName);
		exit(1);
	}
	
	unsigned char ciphertext [8];   
	unsigned char currentChunk [8];
	unsigned char data_block [8];
	int total_output_size = plaintextSize + (8-plaintextSize %8);
	unsigned char write_out_cipher[total_output_size];
	int i = 0;
	
	while(i < numBlocks){
		memcpy(data_block, plaintext + (8*i), 8);
		
		//Is this the last block?
		if(i == numBlocks-1) {
			memset(data_block + (plaintextSize % 8), '\0' , 8 - plaintextSize %8);
		}
		
		memcpy(currentChunk, data_block, 8);
		
		if(i == 0) {
			xOrTwoByteArrays(currentChunk, iv, 8, 8);
			des_encrypt_chunk(key, currentChunk, ciphertext);
			memcpy(write_out_cipher + (i *8), ciphertext, 8);
			//write ciphertext to output file
			fwrite(ciphertext, 1, 8, output_file);
		} else {
			xOrTwoByteArrays(currentChunk, ciphertext, 8, 8);
			des_encrypt_chunk(key, currentChunk, ciphertext);
			memcpy(write_out_cipher + (i *8), ciphertext, 8);
			fwrite(ciphertext, 1, 8, output_file);
		}
		i++;
	}
	
	fclose(output_file);

}


//expands right input to 48 bits
void expansionPermutation(unsigned char datablock[], unsigned char Kn[], unsigned char ret[]) {
    // expansion box
    char E[48] = {
        32,	1,	2,	3,	4,	5,
        4,	5,	6,	7,	8,	9,
        8,	9,	10,	11,	12,	13,
        12,	13,	14,	15,	16,	17,
        16,	17,	18,	19,	20,	21,
        20,	21,	22,	23,	24,	25,
        24,	25,	26,	27,	28,	29,
        28,	29,	30,	31,	32,	1
    };
    
    //for output
    unsigned char expanded_data [8];    //only first 6 bits of every byte are used
    
    int i;
    //E(Rn)
    for(i = 0; i < 48; i++) {
        int val = E[i] -1;
        if(isNthBitSet(datablock[val/8], val % 8)) {
            expanded_data[i/6] |= (1 << 7-i % 6);
        }else {
            expanded_data[i/6] &= ~(1 << 7-i % 6);
        }
    }
    xOrTwoByteArrays(expanded_data, Kn, sizeof(expanded_data), 8);
    unsigned char output [8];
    sBoxLookup(output, expanded_data);
    int P[32] = {
        16,   7,   20,   21,
        29,   12,  28,  17,
        1,    15,  23,  26,
        5,    18,  31,  10,
        2,    8,   24,  14,
        32,   27,   3,   9,
        19,   13,  30,   6,
        22,   11,   4,  25
    };
    
    //permute the final box
    for(i = 0; i < 32; i++) {
        int val = P[i] -1;
        if(isNthBitSet(output[val/4], val % 4)) {
            ret[i/8] |= (1 << 7-i % 8);
        } else {
            ret[i/8] &= ~(1 << 7-i % 8);
        }
    }
}

//initial permutation of message
void initialPermutation(unsigned char M [], unsigned char InitPermutation[]) {
    char IP[64] = {
        58,	50,	42,	34,	26,	18,	10,	2,
        60,	52,	44,	36,	28,	20,	12,	4,
        62,	54,	46,	38,	30,	22,	14,	6,
        64,	56,	48,	40,	32,	24,	16,	8,
        57,	49,	41,	33,	25,	17,	9,	1,
        59,	51,	43,	35,	27,	19,	11,	3,
        61,	53,	45,	37,	29,	21,	13,	5,
        63,	55,	47,	39,	31,	23,	15,	7
    };
    
    int i;
    for(i = 0; i < 64; i++) {
        int val = IP[i];
        if(isNthBitSet(M[(val -1)/8], (val-1)%8)) {
            InitPermutation[i/8] |= (1 << 7-i%8);
        }else {
            InitPermutation[i/8] &= ~(1 << 7-i%8);
        }
    }
}



void createSubKeys(unsigned char key[], unsigned char K[][6]) {
    int PC1[56] = {
        57,	49,	41,	33,	25,	17,	9,
        1,	58,	50,	42,	34,	26,	18,
        10,	2,	59,	51,	43,	35,	27,
        19,	11,	3,	60,	52,	44,	36,
        63,	55,	47,	39,	31,	23,	15,
        7,	62,	54,	46,	38,	30,	22,
        14,	6,	61,	53,	45,	37,	29,
        21,	13,	5,	28,	20,	12,	4
    };
    
    unsigned char N_key [7];
    memcpy(N_key, key, 7);
    
    int n;
    int i;
    //iterate through every byte
    for(i = 0; i < sizeof(PC1)/sizeof(int); i++) {
        //get the bit n we need from key
        
        int n = PC1[i];
        unsigned char tmp = key[n/8];
        //printf("The byte is: %x ", tmp);
        if(isNthBitSet(tmp, n % 8 - 1)) { //bit is set
            //N_key[i/8] ^= (-1 ^ N_key[i/8]) & (1 << i%8);
            N_key[i/8] |= 1 << 8-i%8 -1;
            //printf("SET byte %d, bit %d, the new value is %02x\n", i/8, i%8, N_key[i/8]);
            //printf("1");
        } else {
            N_key[i/8] ^= (-0 ^ N_key[i/8]) & (1 << 8-i%8 -1);
            //printf("CLEAR byte %d, bit %d, the new value is %02x\n", i/8, i%8, N_key[i/8]);
            //printf("0");
        }
    }
    
    //split the array, there are 4 useless bits on each side.
    unsigned char C0 [4];
    unsigned char D0 [4];
    
    memcpy(C0, N_key, 4);
//    print_array_hex(sizeof(C0), C0);
    for(i = 28; i < 56; i++) {
        if(isNthBitSet(N_key[i/8], i % 8)) { //bit is set
            D0[(i-28)/8] |= 1 << 8-(i-28)%8 -1;
//            printf("1");
        } else {
            D0[(i-28)/8] ^= (0 ^ D0[(i-28)/8]) & (1 << 8-(i-28)%8 -1);
//            printf("0");
        }
    }
//    print_array_hex(sizeof(D0), D0);
    
    
    
    /*---------create the pairs {Cn, Dn} from 1 to 16 ----------*/
    //allocate arrays for each pair
    unsigned char C [16][4];
    unsigned char D [16][4];
    //array with number of shift
    int numShifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
    
    for(i = 0; i < 16; i++) {
        char Cn [4];
        char Dn [4];
        if(i == 0) {
            memcpy(Cn, C0, 4);
            memcpy(Dn, D0, 4);
        } else {
            memcpy(Cn, C[i-1], 4);
            memcpy(Dn, D[i-1], 4);
        }


        
        //left shift x times
        int s;
        int k;
        for(s = 0; s < numShifts[i]; s++) {
            //shift each byte left but remember MSB
            int MSB;
            int MSB2;
            /*------------------Cn-------------------------*/
            //byte 3
            if(isNthBitSet(Cn[3], 0)) {
                MSB = 1;
            } else {
                MSB = 0;
            }
            Cn[3] = Cn[3] << 1;
            
            //byte 2
            if(isNthBitSet(Cn[2], 0)) {
                MSB2 = 1;
            } else {
                MSB2 = 0;
            }
            Cn[2] = Cn[2] << 1;
            //set LSB to MSB
            Cn[2] ^= (-MSB ^ Cn[2]) & (1 << 0);
            
            //byte 1
            if(isNthBitSet(Cn[1], 0)) {
                MSB = 1;
            } else {
                MSB = 0;
            }
            Cn[1] = Cn[1] << 1;
            //set LSB to MSB
            Cn[1] ^= (-MSB2 ^ Cn[1]) & (1 << 0);
            
            //Byte 0
            if(isNthBitSet(Cn[0], 0)) {
                MSB2 = 1;
            } else {
                MSB2 = 0;
            }
            Cn[0] = Cn[0] << 1;
            Cn[0] ^= (-MSB ^ Cn[0]) & (1 << 0);
            
            //rotate last bit
            Cn[3] ^= (-MSB2 ^ Cn[3]) & (1 << 4);
            
            /*----------------------------Dn --------------------------------*/
            //byte 3
            if(isNthBitSet(Dn[3], 0)) {
                MSB = 1;
            } else {
                MSB = 0;
            }
            Dn[3] = Dn[3] << 1;
            
            //byte 2
            if(isNthBitSet(Dn[2], 0)) {
                MSB2 = 1;
            } else {
                MSB2 = 0;
            }
            Dn[2] = Dn[2] << 1;
            //set LSB to MSB
            Dn[2] ^= (-MSB ^ Dn[2]) & (1 << 0);
            
            //byte 1
            if(isNthBitSet(Dn[1], 0)) {
                MSB = 1;
            } else {
                MSB = 0;
            }
            Dn[1] = Dn[1] << 1;
            //set LSB to MSB
            Dn[1] ^= (-MSB2 ^ Dn[1]) & (1 << 0);
            
            //Byte 0
            if(isNthBitSet(Dn[0], 0)) {
                MSB2 = 1;
            } else {
                MSB2 = 0;
            }
            Dn[0] = Dn[0] << 1;
            Dn[0] ^= (-MSB ^ Dn[0]) & (1 << 0);
            
            //rotate last bit
            Dn[3] ^= (-MSB2 ^ Dn[3]) & (1 << 4);
        }
        
        memcpy(C[i], Cn, 4);
        memcpy(D[i], Dn, 4);
    }
    
    // PC-2 table (permutation for generating each subkey)
    int PC2[48] = {
        14,	17,	11,	24,	1,	5,	3,	28,
        15,	6,	21,	10,	23,	19,	12,	4,
        26,	8,	16,	7,	27,	20,	13,	2,
        41,	52,	31,	37,	47,	55,	30,	40,
        51,	45,	33,	48,	44,	49,	39,	56,
        34,	53,	46,	42,	50,	36,	29,	32
    };
    
    /*---------------------------------Kn ----------------------------------*/
    int index; 
    int j;
    for(i = 0; i < 16; i++) {
        unsigned char Kn [6];
        for(j = 0; j < 48; j++) {
            index = PC2[j];
            if(index < 29) {    //in Cn
                if(isNthBitSet(C[i][(index-1)/8], (index-1) % 8)) {
                    Kn[j/8] ^= (-1 ^ Kn[j/8]) & (1 << 8-j % 8-1);
                } else { 
                    Kn[j/8] ^= (-0 ^ Kn[j/8]) & (1 << 8-j % 8-1);
                }
            } else {    //in Dn
                int byteNum =(index - 29)/8;
                int bitNum = (index - 29) % 8;

//                printf("val: %d ", index);
//                printf("trying byte %d and bit %d with binary value of: ", byteNum, bitNum);
//                print_char_binary(D[i][byteNum]);
                
                if(isNthBitSet(D[i][byteNum], bitNum)){
                    Kn[j/8] ^= (-1 ^ Kn[j/8]) & (1 << 8-j % 8-1);
                } else {
                    Kn[j/8] ^= (-0 ^ Kn[j/8]) & (1 << 8-j % 8-1);
                }
            }
        }
        memcpy(K[i], Kn, 6); //save the key
    }
}


//fucntion that encrypts 8 bytes at a time
void des_encrypt_chunk(unsigned char key [], unsigned char M [], unsigned char ret []) {
    unsigned char K_tmp [16][6];
    createSubKeys(key, K_tmp);
    
    
    int i, j, offset = 0;
    unsigned char K [16][8];
    for(i = 0; i < 16; i++) {
        for(j = 0; j < 48; j++) {
            if(isNthBitSet(K_tmp[i][j/8], j%8)) {
                K[i][(offset)/6] |= (1 << 7-(offset) % 6);
            } else {
                K[i][(offset)/6] &= ~(1 << 7-(offset) % 6);
            }
            offset++;
        }
        offset = 0;
    }
        
    unsigned char InitPermutation[8];
    initialPermutation(M, InitPermutation); //for return val
    
    //split into left and right halfs
    unsigned char L0 [4];
    unsigned char R0 [4];
    memcpy(L0, InitPermutation, 4);
    memcpy(R0, InitPermutation + 4, 4);
    
    unsigned char L [16][4]; //for all 16
    unsigned char R [16][4];
    
    unsigned char expanded_data[4]; //for the return bits after E-box
    for(i = 0; i < 16; i++) {
        if(i ==0) {
            memcpy(L[i+1], R0, 4);  //L1 = R0
            expansionPermutation(R0, K[i], expanded_data);     //Expand the data to 48bits
            xOrTwoByteArrays(L0, expanded_data, 4, 4);
            memcpy(R[i+1], L0, 4);  //R1 = R0
            //print_array_binary(4, R[i+1]);
        } else {
            memcpy(L[i+1], R[i], 4);
            expansionPermutation(R[i], K[i], expanded_data);
            xOrTwoByteArrays(L[i], expanded_data, 4, 4);
            memcpy(R[i+1], L[i], 4);
        }
    }

    unsigned char revLR [8];
    memcpy(revLR, R[i], 4);
    memcpy(revLR + 4, L[i], 4);
    //print_array_binary(8, revLR);
    
    // final permutation
    char FP[64] = {
        40,	8,	48,	16,	56,	24,	64,	32,
        39,	7,	47,	15,	55,	23,	63,	31,
        38,	6,	46,	14,	54,	22,	62,	30,
        37,	5,	45,	13,	53,	21,	61,	29,
        36,	4,	44,	12,	52,	20,	60,	28,
        35,	3,	43,	11,	51,	19,	59,	27,
        34,	2,	42,	10,	50,	18,	58,	26,
        33,	1,	41,	9,	49,	17,	57,	25
    };
    
    unsigned char encrypted_text [8];
    
    for(i = 0; i < 64; i++) {
        int val = FP[i] -1;
        if(isNthBitSet(revLR[val/8], val % 8)) {
            encrypted_text[i/8] |= (1 << 7-i % 8);
        } else {
            encrypted_text[i/8] &= ~(1 << 7-i % 8);
        }
    }
    
    memcpy(ret, encrypted_text, 8);
}//end decrypt
