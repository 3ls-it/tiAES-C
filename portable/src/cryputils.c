//cryputils.c
//(c) 2023 J Adams jfa63[at]duck[dot]com
//Released under the 2-clause BSD license.

#include <openssl/rand.h>

#include "core.h"


//copy new state to state
void
cpyns_st()
{
    int r,c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            st[r][c] = ns[r][c];
        }
    }
}

//copy temp block to iv
void
cpytb_iv()
{
    int r,c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            iv[r][c] = tb[r][c];
        }
    }
}

//copy state to temp block
void
cpyst_tb()
{
    int r,c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            tb[r][c] = st[r][c];
        }
    }
}

//copy state to IV
void
cpyst_iv()
{
    int r,c;
    for (r=0; r<4; r++) {
        for (c=0; c<4; c++) {
            iv[r][c] = st[r][c];
        }
    }
}

// Generate our safe random number with OpenSSL
void
gen_rand(unsigned char* buff)
{
    // Initialize the random number generator
    RAND_poll();

    // Generate 64byte random number
    if (RAND_bytes(buff, 64) != 1) {
        printf("Error generating random number.\n");
        // handle the error 
    }
}

// Get a random IV for CBC
void
get_iv()
{
    int i;
    uchar* rn = malloc(64);
    
    // Generat rand num
    gen_rand(rn);
    // Digest rand num
    uchar* hsh = SHA256(rn);
    // Clear mem location of rand num
    explicit_bzero(rn, 64*sizeof(rn[0]));

    // Load IV
    i = 0;
    for (int r=0; r<4; r++) {
        for (int c=0; c<4; c++) {
            iv[r][c] = hsh[i];
            i++;
        }
    }
    // Clear mem location of hash
    explicit_bzero(hsh, 32*sizeof(hsh[0]));
}
