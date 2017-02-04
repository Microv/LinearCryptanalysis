#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <openssl/aes.h>

#define KeyLength 			16
#define BlockSize 			2 		// in bytes
#define NumRounds 			4
#define KnownPlaintextNum 	100000 //10000


char getBit(char x, int index);
void setBit(char *x, int index, char bit);
void enc_toy(char *plaintext, char *ciphertext, char *key);
void dec_toy(char *ciphertext, char *plaintext, char *key); 
void linear_attack(int fd, unsigned char *tps, float *bias);
