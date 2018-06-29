#pragma once

#include "stdafx.h"


#define WARNING     1        //put 1 if you want the MessageBox to be displayed in case of error, else put 0
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)


void HexStringToHexValue						(char *input_str, uint8_t *output_hex_values, int input_string_len);			//Turns the string into hex values, the buffer has to be allocated
void PrintHex									(uint8_t* hex,int buffer_bytes);												//Prints the hex values of a buffer
INT8 CheckHexString								(LPVOID str_add, INT str_len);
UINT64 RandomInterval							(UINT64 rand_num, UINT64 itv_max, UINT64 itv_min);
INT8 SecureFileDelete							(int, int,char *);																//DO NOT USE, looking for a replacement

void ErrorExit									(LPTSTR lpszFunction);															//Automatically calls GetLastError() and prints the output message in a Message Box

INT AnsiX293ForcePad							(HANDLE heap, LPVOID ptr, INT buf_len, UINT8 multiplier);						//Pads The selected buffer using AnsiX293, the handle is needed for reallocation of the pointer, buf_len is the INPUT buffer lenght, multiplier is the value to pad the buffer to
INT AnsiX293ForceReversePad						(HANDLE heap, LPVOID ptr, INT buf_len);											//Reverses the pad, the handle is needed for reallocation of the pointer, buf_len is the INPUT buffer lenght (padded)

CHAR PressAnyKey								(HANDLE hstdin, HANDLE hstout, const WCHAR* prompt);
int ScrollByRelativeCoord						(HANDLE hStdout, int iRows);
void SetColor									(HANDLE hStdOut, int ForgC);
void ClearOutputBuffer							(HANDLE hConsole);
void NewLine									(HANDLE hStdout);
void ScrollScreenBuffer							(HANDLE h, INT x, CONSOLE_SCREEN_BUFFER_INFO csbiInfo);
