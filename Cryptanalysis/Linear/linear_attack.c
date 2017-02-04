#include "linear-cryptanalysis.h"
#include "boxes-ref.h"

/*
	fd = file descriptor of plaintext-ciphertext samples to use in the attack
	tps = target partial subkey to find (bit to be recovered from the last subkey)
	bias = bias for the target partial subkey found
*/
void linear_attack(int fd, unsigned char *tps, float *bias) {
	
	int subkey;
	char u;
	char r;
	int count[256], i;
	char plaintext[BlockSize], ciphertext[BlockSize];
	
	memset(count, 0, 256*sizeof(int));
	lseek(fd, 0, SEEK_SET);
	while (read(fd, plaintext, BlockSize) > 0) {
		lseek(fd, 1, SEEK_CUR);
		read(fd, ciphertext, BlockSize);
		lseek(fd, 1, SEEK_CUR);
		
#ifdef VERBOSE
		printf("Analysing couple ");
		for(i = 0; i < BlockSize; i++) printf("%02x", (unsigned char) plaintext[i]);
		printf(" ");
		for(i = 0; i < BlockSize; i++) printf("%02x", (unsigned char) ciphertext[i]);
		printf("\n");
#endif	

		for(subkey = 0; subkey < 256; subkey++) {
#ifdef VERBOSE
		printf("Analysing subkey %02x\n", (unsigned char) subkey);
#endif	
			u = sinv[(ciphertext[0] & 0x0F) ^ (subkey >> 4)] << 4;
			u ^= sinv[(ciphertext[1] & 0x0F) ^ (subkey & 0x0F)];
		
			r = getBit(u, 1) ^ getBit(u, 3) ^ getBit(u, 5) ^ getBit(u, 7)
			^ getBit(plaintext[0], 4) ^ getBit(plaintext[0], 6) ^ getBit(plaintext[0], 7);
		
			if(!r) count[subkey]++;	// the linear expression holds true		
		}	
	}
	
#ifdef VERBOSE	
	for(i = 0; i < 256; i++) {
		if(i%8 == 0) printf("\n");
		printf("%d\t", count[i]);
	}
	printf("\n");		 
#endif
	
	int maxDist = 0; // difference from half the number of plaintext/ciphertext samples
	int maxCount = 0; // count which differs the greatest from half the number of plaintext/ciphertext samples

	for(i = 1; i < 256; i++)
		if(abs(count[i] - KnownPlaintextNum/2) >= maxDist) {
			maxDist = abs(count[i] - KnownPlaintextNum/2);
			maxCount = i;
		}
	
	*tps = (unsigned char) maxCount;
	*bias = (float)maxDist/KnownPlaintextNum;
}

