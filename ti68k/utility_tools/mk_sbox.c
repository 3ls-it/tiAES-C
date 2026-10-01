//mk_sbox.c
//output the sbox table

#include "gfmath.h" 

int main() {
	
	uchar e;
	uint i;

	//display table
	printf("sbox table:\n");
	for (i=0; i<256; i++) {
		e=sbox(i);
		printf("%hhu,",e);
	}
	printf("\n");

	return 0;
}
