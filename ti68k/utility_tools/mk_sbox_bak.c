//mk_sbox.c
//output the sbox and invers sbox
#include "gfmath.h" 

//uchar sb[256];
//uchar sbi[256];
uchar i,c;


int main() {

	//load tables
	/*
	for (i=0; i<256; i++) {
		sb[i]=sbox(i);
	}

	for (i=0; i<256; i++) {
		sbi[sb[i]]=i;
	}
	*/
	//diplay tables
	printf("sbox table\n");
	for (i=0; i<256; i++) {
		c=sbox(i);
		printf("%hhu",c);
		printf("%c",',');
	}
	printf("Done\n");

	/*
	printf("\n");
	printf("inverse sbox table\n");
	for (int i=0; i<256; i++) {
		c=sbi[i];
		printf("%hhu",c);
		printf("%c",',');
	}
	printf("\n");
	*/

	return 0;
}
