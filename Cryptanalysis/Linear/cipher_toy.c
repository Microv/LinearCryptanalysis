#include "linear-cryptanalysis.h"
#include "boxes-ref.h"

// index = 0, 1, ..., 7 from  most significant bit
char getBit(char x, int index) {

	return (x >> (7-index)) & 0x01;	
	
}

void setBit(char *x, int index, char bit) {

	char old_bit = getBit(*x, index);
	char mask; 
	
	if(!old_bit && bit)
		*x |= (bit << 7) >> index;
	else 
		if(old_bit && !bit) {
			mask = 0xFF ^ ((0x01 << 7) >> index);	
			*x &= mask;
		}
	
}

void enc_toy(char *plaintext, char *ciphertext, char *key) {
	
	int round, i, j; 
	char *tmpCiph = malloc(BlockSize);
	char *t = malloc(BlockSize);
	char t0, t1, t2, t3; 
	
	memcpy(tmpCiph, plaintext, BlockSize);
	memset(ciphertext, 0, BlockSize);

#ifdef VERBOSE	
	printf("Plaintext: \n");
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(plaintext[j], i));
	}
	printf("\n");
#endif	
	
	for(round = 0; round < NumRounds-1; round++) {	
		
		// Apply key
		for(i = 0; i < BlockSize; i++)
			tmpCiph[i] ^= key[BlockSize*round+i]; 		

#ifdef VERBOSE
		printf("Round %d\n", round+1);
		printf("\tApplying Key: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i < 8; i++)
				printf("%d ", getBit(tmpCiph[j], i));
		}
		printf("\n");
#endif
		
		// Apply S-Boxes
		t0 = s[(tmpCiph[0] >> 4) & 0x0F] << 4; 
		t1 = s[tmpCiph[0] & 0x0F]; 
		t2 = s[(tmpCiph[1] >> 4) & 0x0F] << 4;
		t3 = s[tmpCiph[1] & 0x0F];
		t[0] = t0 ^ t1;
		t[1] = t2 ^ t3;
		
#ifdef VERBOSE
		printf("\tApplying S-Boxes: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i< 8; i++)
				printf("%d ", getBit(t[j], i));
		}
		printf("\n");
#endif

		// Apply permutation
		for(j = 0; j < BlockSize * 8; j++)
			setBit(&tmpCiph[p[j]/8], p[j]%8, getBit(t[j/8], j%8));
			
#ifdef VERBOSE
		printf("\tApplying Permutation: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i< 8; i++)
				printf("%d ", getBit(tmpCiph[j], i));
		}
		printf("\n");
#endif			
			
	}
	
	// Last round
	// Apply key
	for(i = 0; i < BlockSize; i++)
		tmpCiph[i] ^= key[BlockSize*round+i]; 		

#ifdef VERBOSE
	printf("Last round: \n");
	printf("\tApplying Key: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(tmpCiph[j], i));
	}
	printf("\n");
#endif	
	
	// Apply S-Boxes	
	t0 = s[(tmpCiph[0] >> 4) & 0x0F] << 4; 
	t1 = s[tmpCiph[0] & 0x0F]; 
	t2 = s[(tmpCiph[1] >> 4) & 0x0F] << 4;
	t3 = s[tmpCiph[1] & 0x0F];
	ciphertext[0] = t0 ^ t1;
	ciphertext[1] = t2 ^ t3; 		

#ifdef VERBOSE
	printf("\tApplying S-Boxes: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(ciphertext[j], i));
	}
	printf("\n");
#endif	

	// Apply key
	round++;
	for(i = 0; i < BlockSize; i++)
		ciphertext[i] ^= key[BlockSize*round+i];

#ifdef VERBOSE
	printf("\tApplying Key: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(ciphertext[j], i));
	}
	printf("\n");
#endif		
}


void dec_toy(char *ciphertext, char *plaintext, char *key) {
	
	int round, i, j; 
	char *tmpCiph = malloc(BlockSize);
	char *t = malloc(BlockSize);
	char t0, t1, t2, t3; 
	
	memcpy(tmpCiph, ciphertext, BlockSize);
	memset(plaintext, 0, BlockSize);

#ifdef VERBOSE	
	printf("Ciphertext: \n");
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(ciphertext[j], i));
	}
	printf("\n");
#endif	

	round = 0;
	for(i = 0; i < BlockSize; i++)
		tmpCiph[i] ^= key[BlockSize*round+i]; 
	
	#ifdef VERBOSE
	printf("First round: \n");
	printf("\tApplying Key: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(tmpCiph[j], i));
	}
	printf("\n");
#endif	
		
	t0 = sinv[(tmpCiph[0] >> 4) & 0x0F] << 4; 
	t1 = sinv[tmpCiph[0] & 0x0F]; 
	t2 = sinv[(tmpCiph[1] >> 4) & 0x0F] << 4;
	t3 = sinv[tmpCiph[1] & 0x0F];
	tmpCiph[0] = t0 ^ t1;
	tmpCiph[1] = t2 ^ t3;	
		
#ifdef VERBOSE
	printf("\tApplying S-Boxes: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(tmpCiph[j], i));
	}
	printf("\n");
#endif
		
	for(round = 1; round < NumRounds; round++) {	
		for(i = 0; i < BlockSize; i++)
			tmpCiph[i] ^= key[BlockSize*round+i]; 		

#ifdef VERBOSE
		printf("Round %d\n", round+1);
		printf("\tApplying Key: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i < 8; i++)
				printf("%d ", getBit(tmpCiph[j], i));
		}
		printf("\n");
#endif
		
		for(j = 0; j < 16; j++)
			setBit(&t[p[j]/8], p[j]%8, getBit(tmpCiph[j/8], j%8));
#ifdef VERBOSE
		printf("\tApplying Permutation: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i< 8; i++)
				printf("%d ", getBit(t[j], i));
		}
		printf("\n");
#endif			
		
		t0 = sinv[(t[0] >> 4) & 0x0F] << 4; 
		t1 = sinv[t[0] & 0x0F]; 
		t2 = sinv[(t[1] >> 4) & 0x0F] << 4;
		t3 = sinv[t[1] & 0x0F];
		tmpCiph[0] = t0 ^ t1;
		tmpCiph[1] = t2 ^ t3;
		
#ifdef VERBOSE
		printf("\tApplying S-Boxes: \n");
		for(j = 0; j < BlockSize; j++) {
			printf("\t");
			for(i=0; i< 8; i++)
				printf("%d ", getBit(tmpCiph[j], i));
		}
		printf("\n");
#endif
			
	}
	
	for(i = 0; i < BlockSize; i++)
		tmpCiph[i] ^= key[BlockSize*round+i]; 		

#ifdef VERBOSE
	printf("Last round: \n");
	printf("\tApplying Key: \n");	
	for(j = 0; j < BlockSize; j++) {
		printf("\t");
		for(i=0; i< 8; i++)
			printf("%d ", getBit(tmpCiph[j], i));
	}
	printf("\n");
#endif	
	memcpy(plaintext, tmpCiph, BlockSize);	
}


