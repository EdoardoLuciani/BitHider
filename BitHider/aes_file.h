#pragma once

#include "stdafx.h"
#include "aes.hpp"
#include "CBBS.hpp"	
#include "cryptoTK.hpp"


#define ALLOC_FAILED (DWORD)0xB0000020L
#define OPEN_ALG_FAILED (DWORD)0xB0000030L
#define ENCRYPT_DECRYPT_FAILED (DWORD)0xB0000040L
#define SET_CHAIN_MODE_FAILED (DWORD)0xB0000050L
#define CLOSE_ALG_FAILED (DWORD) 0xB0000060L
#define DEALLOC_FAILED (DWORD)0xB0000070L

#define SEED_LEN 32
#define BLOCK_DIM 104857600
#define BLOCK_DIM_DOUBLE 104857600.0
#define MAX_STR_LEN 256
#define IV_LEN 16               //IV MUST be 16 Bytes, not my fault, but the AES_256 algorithm
#define KEY_LEN 32				//KEY MUST be 32 Bytes  (AES-256 means 256 bit key   256/8=32)


enum AesFileSelection {
	Encrypt,
	Decrypt
};


class AesFile {

public:

	AesFile(LPCWSTR path, AesFileSelection value);
	~AesFile();

	int InitGen();							//Inizialize random generator

	void GenerateIv();						//generate a random IV from BBS, IMPORTANT: init_gen HAS TO BE CALLED FIRST
	void GenerateKey();						//generate a random KEY from BBS, IMPORTANT: init_gen HAS TO BE CALLED FIRST

	void GetIv();							//get IV from user input
	void GetKey();							//get KEY from user input

	int ExecSelectedAction();				//execute the action defined by enum list

	void PrintInfo();						//prints out key and iv
	
private:

	void EncryptFileC();					//encrypt file
	void DecryptFileC();					//decrypt file

	pCBBS BBS;								//pointer to random generator class

	LPVOID iv_;								//pointer to IV
	LPVOID key_;							//pointer to KEY

	HANDLE input_file_;						//input file

	HANDLE output_file_;					//output file

	HANDLE hIn, hOut;

	SYSTEM_INFO sSysInfo_;

	DWORD old_protect_value_, input_console_mode_, cRead, cWritten;

	NTSTATUS error_;

	BCRYPT_KEY_HANDLE key_handle_;

	AesFileSelection value_;

	BCRYPT_ALG_HANDLE algorithm_;
};