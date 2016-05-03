#include <stdlib.h>

/*

Travis Machacek
John Flickinger

*/
//Convert ascii to hex 
int ascii_to_hex(unsigned char c){
   int num = c;
   if(num < 58 && num > 47){

      return num - 48;
   } 
   if(num < 103 && num > 96) {

      return num - 87;
   }
   return num;
}//end ascii_to_hex


// Key reader function to turn key into hex so we can use it
void readKey(char* key,char* output){
   //printf("Key: %s\n",key);
   unsigned char firstBit,secondBit;
   unsigned char sum,hexOutput[16];
   int i,j;
  for(j = 0; j < 8; j++) {
   for(i = j*2;i < (j*2) + 1;i++) {
       firstBit = ascii_to_hex((unsigned char)key[i]);
       secondBit = ascii_to_hex((unsigned char)key[i+1]);
       sum = firstBit<<4 | secondBit;
       hexOutput[j] = sum;
       //printf("%02x\n",finalHex[j]);
   }

  }

   memcpy(output,hexOutput,8);
}//end keyRead




//generate random key if user needs one

void randomKeyGen() {
	int randNum;
	int i;
	srand(time(NULL));
	char standard[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	for(i = 0; i < 16; i++){
  		randNum = rand()%16;
  		printf("%c",standard[randNum]);
	}
	
	printf("\n");

}//end randomKeyGen

