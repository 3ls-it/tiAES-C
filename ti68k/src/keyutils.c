// keyutils.c
//(c) 2023 2024 J Adams jfa63[at]duck[dot]com
//Released under the 2-clause BSD license.
/*
Functions are labeled with the FIPS 197
nomenclature.
*/

#include "core.h"

// Round-key constants
unsigned char rcons[]={0,1,2,4,8,16,32,64,128,27,54,108,216};

// Temporary round-key word (vector)
unsigned char rcwd[]={0,0,0,0};

word tmp,wrow;

/* SubWord() */
void
subword()
{
    int i;
    for (i=0; i<4; i++) {
        tmp[i] = sbox[tmp[i]];
    }
}

/* RotWord() */
void
rotword()
{
    uchar t = tmp[0];
    tmp[0] = tmp[1];
    tmp[1] = tmp[2];
    tmp[2] = tmp[3];
    tmp[3] = t;
}

void
gettmp(int r)
{
    int c;
    for (c=0; c<4; c++) {
        tmp[c] = w[r][c];
    }
}

void
getrow(int r)
{
    int c;
    for (c=0; c<4; c++) {
        wrow[c] = w[r][c];
    }
}

void
putrow(int r)
{
    int c;
    for (c=0; c<4; c++) {
        w[r][c] = wrow[c];
    }
}


/*
KeyExpansion() to generate the key schedule.
*/
void
ke(char* key)
{
    int r,c,t,e;
    // Use unsigned int as we do math with  'i'   
    unsigned int i;
    nk = 8;
    nr = 14;

    //load primary key at the top of key schedule
    i = 0;
    for (r=0; r<nk; r++) {
        for (c=0; c<NB; c++) {
            w[r][c] = key[i];
            i++;
        }
    }

    //expand key material
    for (i=nk; i<60; i++) {
        gettmp(i-1);
        if (i % nk == 0) {
            rotword();
            subword();
            rcwd[0] = rcons[i/nk];
            //temprow xor rcword
            for (t=0; t<4; t++) {
                tmp[t] = tmp[t] ^ rcwd[t];
            }
        } else if ((nk > 6) && (i % nk)==4) {
            subword();
        }
        getrow(i-nk);
        //wrow xor temprow
        for (e=0; e<4; e++) {
            wrow[e] = wrow[e] ^ tmp[e];
        }
        putrow(i);
    }
}// end of ke()

