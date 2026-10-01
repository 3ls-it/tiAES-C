//mk_multtabs.c
//output the GF256 multiplication tables

#include "gfmath.h" 

uchar m2[256];
uchar m3[256];
uchar m9[256];
uchar m11[256];
uchar m13[256];
uchar m14[256];

int main() {
	
	uchar e;
	uint i;

	//load x2 table
	for (i=0; i<256; i++) {
		m2[i]=xtime(i);
	}

	//load x3 table
	for (i=0; i<256; i++) {
		m3[i]=xtime3(i);
	}

	//load x9 table
	for (i=0; i<256; i++) {
		m9[i]=xmult(9,i);
	}

	//load x11 table
	for (i=0; i<256; i++) {
		m11[i]=xmult(11,i);
	}

	//load x13 table
	for (i=0; i<256; i++) {
		m13[i]=xmult(13,i);
	}

	//load x14 table
	for (i=0; i<256; i++) {
		m14[i]=xmult(14,i);
	}


	//display tables
	printf("x2 table:\n");
	for (i=0; i<256; i++) {
		e=m2[i];
		printf("%hhu,",e);
	}

	printf("\n");
	printf("x3 table:\n");
	for (i=0; i<256; i++) {
		e=m3[i];
		printf("%hhu,",e);
	}

	printf("\n");
	printf("x9 table:\n");
	printf("\n");
	for (i=0; i<256; i++) {
		e=m9[i];
		printf("%hhu,",e);
	}

	printf("\n");
	printf("x11 table:\n");
	printf("\n");
	for (i=0; i<256; i++) {
		e=m11[i];
		printf("%hhu,",e);
	}

	printf("\n");
	printf("x13 table:\n");
	printf("\n");
	for (i=0; i<256; i++) {
		e=m13[i];
		printf("%hhu,",e);
	}

	printf("\n");
	printf("x14 table:\n");
	printf("\n");
	for (i=0; i<256; i++) {
		e=m14[i];
		printf("%hhu,",e);
	}
	printf("\n");

	return 0;
}
