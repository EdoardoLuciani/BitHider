#pragma once

#include "stdafx.h"


#define WARNING     1        //put 1 if you want the MessageBox to be displayed in case of error, else put 0
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)


int8_t win_bcrypto_seed							(int,   BYTE *  );						//The buffer HAS to be allocated
int8_t win_crypto_seed							(int,   BYTE *  );						//Deprecated use win_bcrypto_seed instead, the buffer HAS to be allocated
int8_t hash_crypto_seed							(int,   BYTE *  );						//not active, the buffer HAS to be allocated
void hex_value_string_to_hex_value				(char*,uint8_t*,int);					//The buffers has to be allocated
void print_hex									(uint8_t*,int);
char* get_filename								(char [],int len);						//dangerous, the buffer HAS to be allocated
void SetColor									(int);
uint64_t random_interval						(unsigned long long int, int, int);
int8_t secure_file_delete						(int, int,char *);


int Init_Error									();										//WINDOWS API FUNCTIONS
void DisplayError								(LPTSTR);
void ErrorExit									(LPTSTR);


