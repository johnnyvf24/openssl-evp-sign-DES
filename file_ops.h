#ifndef FILE_OPS_H_INCLUDED
#define FILE_OPS_H_INCLUDED

extern int debug;

char * read_file(char * fileName, unsigned int *retLength);
void write_file(char * fileName, char * content, int size);

#endif