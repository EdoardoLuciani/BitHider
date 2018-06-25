#pragma once

#include "stdafx.h"


#define WARNING     1        //put 1 if you want the MessageBox to be displayed in case of error, else put 0
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)


void HexStringToHexValue						(char*,uint8_t*,int);					//The buffers has to be allocated
void PrintHex									(uint8_t*,int);
void SetColor									(int);
UINT64 RandomInterval							(UINT64, UINT64, UINT64);
INT8 SecureFileDelete							(int, int,char *);						//DO NOT USE, looking for a replacement

void ErrorExit									(LPTSTR);
INT AnsiX293ForcePad							(HANDLE, LPVOID, INT, UINT8);			//The buffer reallocates automatically
INT AnsiX293ForceReversePad						(HANDLE, LPVOID, INT);					//The buffer reallocates automatically


