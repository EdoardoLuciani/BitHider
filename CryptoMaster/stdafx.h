// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>				//Standard Libraries 
#include <stdlib.h>
#include <tchar.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <strsafe.h>

#include <windows.h>			//Windows Specific API
#include <Wincrypt.h>
#include <bcrypt.h>

#include <gmp.h>				//Math Libs
#include <mpir.h>
#include <mpfr.h>			


#define SEED_LEN 32
#define BLOCK_DIM 104857600
#define MAX_STR_LEN 256
#define IV_LEN 16               //IV MUST be 16 Bytes, not my fault, but the AES_256 algorithm
#define KEY_LEN 32				//KEY MUST be 32 Bytes  (AES-256 means 256 bit key   256/8=32)



// TODO: reference additional headers your program requires here
