//Globals and prototypes for GF256 math routines

#include <stdio.h>
#include <stdlib.h>

typedef unsigned int uint;
typedef unsigned char uchar;

//prototypes
extern uchar xtime(uchar n);
extern uchar xtime3(uchar n);
extern uchar xmult_nt(uchar a, uchar b);
extern uchar xmult(uchar a, uchar b);
extern uchar sbox(uchar n);
extern uchar xpow(uchar b, uchar e);
