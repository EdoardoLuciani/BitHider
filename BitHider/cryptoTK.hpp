#pragma once

#include "stdafx.h"


#define WARNING     1        //put 1 if you want the MessageBox to be displayed in case of error, else put 0
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)


int8_t WinBCryptoSeed							(int,   BYTE *  );						//The buffer HAS to be allocated
int8_t WinCryptoSeed							(int,   BYTE *  );						//Deprecated use win_bcrypto_seed instead, the buffer HAS to be allocated
void HexStringToHexValue						(char*,uint8_t*,int);					//The buffers has to be allocated
void PrintHex									(uint8_t*,int);
char* GetFilename								(char [],int len);						//dangerous, the buffer HAS to be allocated
void SetColor									(int);
uint64_t RandomInterval							(unsigned long long int, int, int);
int8_t SecureFileDelete							(int, int,char *);


int InitError									();										//WINDOWS API FUNCTIONS
void DisplayError								(LPTSTR);
void ErrorExit									(LPTSTR);


