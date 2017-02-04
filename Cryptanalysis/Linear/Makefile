#CFLAGS=-c -std=c99 -g -DVERBOSE
CFLAGS=-c -std=c99 
LDFLAGS=-lcrypto -ldl -lm

OBJ=cipher_toy.o linear_attack.o
EXE=main enc_test

all: ${EXE}

main: ${OBJ} main.o 
	gcc ${OBJ} main.o -o $@ ${LDFLAGS} 

enc_test: ${OBJ} enc_test.o 
	gcc ${OBJ} enc_test.o -o $@ ${LDFLAGS} 
	
clean:  
	rm -f ${OBJ}  ${EXE} main.o cipher.o linear_attack.o enc_test.o



