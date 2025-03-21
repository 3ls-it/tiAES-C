//core.h
//(c) 2023 2024 J Adams jfa63[at]duck[dot]com
//Released under the 2-clause BSD license.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CRYPUTILS_H
#define CRYPUTILS_H
#include "cryputils.h"
#endif

//word bytes
#define NB 4

//data types
typedef unsigned int uint;
typedef unsigned char uchar;
typedef unsigned char block[4][4];
typedef unsigned char word[4];

//Globals
block st,tb,ns,iv; //state blocks
unsigned int nk = 8;
unsigned int nr = 14;
unsigned char w[60][4];

