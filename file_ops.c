#include "file_ops.h"
#include <stdio.h>
#include <stdlib.h>
/**
 * @brief Read a file.
 * @param fileName, the name of the file
 * @return the text from the file
 */
char * read_file(char * fileName) {
    long int size = 0;
    FILE *file = fopen(fileName, "rb");

    if(!file) {
        fputs("File error.\n", stderr);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    char * result = (char *) malloc(size+1);
    result[size] = '\0';    //terminate with a null character
    if(!result) {
        fputs("Memory error.\n", stderr);
		exit(1);
    }

    if(fread(result, sizeof(char), size, file) != size) {
        fputs("Read error.\n", stderr);
		exit(1);
    }

    fclose(file);
    return result;
}

/**
 * @brief Write X amount of chars to a file
 * @param fileName, the name of the file
 * @param content, the content to write X from
 * @param size, the X amount of chars
 */
void write_file(char * fileName, char * content, int size) {
	FILE *fp = fopen(fileName, "w");
	if(fp == NULL) {
		printf("Error! Could not open file %s", fileName);
		exit(1);
	}
	fwrite(content, sizeof(char), size, fp);
}