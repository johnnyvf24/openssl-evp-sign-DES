/*

Travis Machacek
John Flickinger

Print functions for debug purposes
*/

/**
 * @brief Print one byte in binary
 */
void print_char_binary(unsigned char x) {
    int i;
    for(i=0; i < 8; i++) {
        printf("%d", !!((x << i) & 0x80));
    }
    printf(" ");
}

/**
 * @brief Print out an array in bytes
 * @param size, the number of bytes
 */
void print_array_binary(int size, unsigned char * arr) {
    int i = 0;
    for( i = 0; i < size; i++) {
        print_char_binary(arr[i]);
    }
    printf("\n");
}


/**
 * @brief utility to print out hexadecimal array.
 * @param size, the number of elements in the array
 * @param arr, the array to print
 */
void print_array_hex(int size, unsigned char * arr) {
	//printf("STRING: %s\n",arr);
	//printf("SIZE: %d\n",size);
    int i = 0;
    for( i = 0; i < size; i++) {
        printf("%02x", arr[i]);
    }
    printf("\n");
}