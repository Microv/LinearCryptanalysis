#include "linear-cryptanalysis.h"

int main (void) {
	
	int i;
	char key[]={0x00,0x01,0x02,0x03,
                0x04,0x05,0x06,0x08,
                0x14,0x15,0x16,0x17,
                0xa4,0xa5,0xa6,0xa7};
	char key_dec[]=
				{0x14,0x15,0x06,0x08,
				 0x04,0x05,0x02,0x03,
				 0x00,0x01 
				};
	
	
	char plaintext[] = {0x02, 0x05};
	char *ciphertext;
	char *newplain;
	
	
	printf("Plaintest: ");
	for(i = 0; i < 2; i++)
		printf("%02x ", (unsigned char)plaintext[i]);
	printf("\n");
	
	ciphertext = malloc(2);
	enc_toy(plaintext, ciphertext, key);
	
	printf("Ciphertext: ");
	for(i = 0; i < 2; i++)
		printf("%02x ", (unsigned char)ciphertext[i]);
	printf("\n");
	
	newplain = malloc(2);
	dec_toy(ciphertext, newplain, key_dec);
	
	printf("Plaintext after decription: ");
	for(i = 0; i < 2; i++)
		printf("%02x ", (unsigned char)newplain[i]);
	printf("\n");
}
