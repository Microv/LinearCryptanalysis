#include "linear-cryptanalysis.h"

int main (void) {
	
	char *plaintext=malloc(2);
	char *ciphertext=malloc(2);
	int i;
	int count;
	int fd;
	
	/*char key[]={0x00,0x01,0x02,0x03,
                0x04,0x05,0x06,0x08,
                0x14,0x15,0x16,0x17,
                0xa4,0xa5,0xa6,0xa7};*/
                
    char key[2*(NumRounds+1)];
    time_t t;
   	srand((unsigned) time(&t)); //Intializes random number generator   
   	
   	printf("\nNumber of known plaintext-ciphertext samples: %d\n", KnownPlaintextNum);
   	printf("Key: ");         
    for(i = 0; i < 2*(NumRounds+1); i++) {
    	key[i] = rand() % 256;
    	printf("%02x ", (unsigned char)key[i]);
    }           
	printf("\n\nLast subkey:\t%02x %02x\n", (unsigned char)key[8], (unsigned char)key[9]);
	printf("Expected target partial subkey: %01x%01x\n", 
	(unsigned char)(key[8]&0x0F), (unsigned char)(key[9]&0x0F));
	
	fd = open("known_plaintext", O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);
	for(count = 0; count < KnownPlaintextNum; count++) {
		plaintext[0] = rand() % 256;
		plaintext[1] = rand() % 256;
		enc_toy(plaintext, ciphertext, key);
		
		write(fd, plaintext, 2);
		write(fd, " ", 1);
		write(fd, ciphertext, 2);
		write(fd, "\n", 1);
	}	
	fsync(fd);
	
	unsigned char tps;
	float bias;
	linear_attack(fd, &tps, &bias);			
	
	printf("Found partial subkey:\t\t%02x\n", tps);
	printf("\nExpected bias:\t%f\n", (float)1/32);
	printf("Found bias:\t%f\n\n", bias);

}
