#include "des_utils.h"

/*  

Travis Machacek
John Flickinger

This is where we perform most of our bit manipulation
operations.

*/
//check to see if bit is set
int isNthBitSet (unsigned char c, int n) {
    static unsigned char mask[] = {128, 64, 32, 16, 8, 4, 2, 1};
    return ((c & mask[n]) != 0);
}


/**
 * @brief exclusive-or two byte arrays and place output in array1. Only works if array 2 is longer or 
 * of equal size to array 1.
 * @param arr1, first array
 * @param arr2, sencond array
 */

void xOrTwoByteArrays(unsigned char arr1[], unsigned char arr2[], int size1, int size2) {
    if(size2 < size1) {
        printf("error");
        return;
    }
    
    int i;
    for(i = 0; i < size1; i++) {
        arr1[i] ^= arr2[i];
    }
}

//function to look up positions from sbox
void sBoxLookup(unsigned char * sOutput, unsigned char * b)
{
    int i, j;
    for(i = 0; i < 8; i++) {
        int row, col;
        int in0, in1;
        int colin[4];
        int cin0, cin1, cin2, cin3;
        row = col = 0x00;
//        in0 = (b[i] >> 5) & 0x01; // first
        if(isNthBitSet(b[i], 0)) {
            in0 = 1;
        } else {
            in0 = 0;
        }
//        in1 = (b[i] >> 0) & 0x01; // second
        if(isNthBitSet(b[i], 5)) {
            in1 = 1;
        } else {
            in1 = 0;
        }
        //middle 4 bits
        if(isNthBitSet(b[i], 1)) {
            cin0 = 1;
        } else {
            cin0 = 0;
        }
        if(isNthBitSet(b[i], 2)) {
            cin1 = 1;
        } else {
            cin1 = 0;
        }
        if(isNthBitSet(b[i], 3)) {
            cin2 = 1;
        } else {
            cin2 = 0;
        }
        if(isNthBitSet(b[i], 4)) {
            cin3 = 1;
        } else {
            cin3 = 0;
        }


        row ^= (-(in0) ^ row) & (1 << 1);
        row ^= (-(in1) ^ row) & (1 << 0);

        col ^= (-(cin0) ^ col) & (1 << 3);
        col ^= (-(cin1) ^ col) & (1 << 2);
        col ^= (-(cin2) ^ col) & (1 << 1);
        col ^= (-(cin3) ^ col) & (1 << 0);

        if(row == 0) {
            sOutput[i] = SBOXMAP[i][col];
            sOutput[i] = sOutput[i] << 4;
//            printf("row: %d col: %d soutput: %d\n", row, col, sOutput[i]);
        }
        if(row == 1) {

            sOutput[i] = SBOXMAP[i][col + 16];
            sOutput[i] = sOutput[i] << 4;
//            printf("row: %d col: %d soutput: %d\n", row, col, sOutput[i]);
        }
        if(row == 2) {
            sOutput[i] = SBOXMAP[i][col + 32];
            sOutput[i] = sOutput[i] << 4;
//            printf("row: %d col: %d soutput: %d\n", row, col, sOutput[i]);
        }
        if(row == 3) {
            sOutput[i] = SBOXMAP[i][col + 48];
            sOutput[i] = sOutput[i] << 4;
//            printf("row: %d col: %d soutput: %d\n", row, col, sOutput[i]);
        }
    } // end for

} // end SboxLookup