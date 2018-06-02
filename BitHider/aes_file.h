#pragma once

#include "stdafx.h"
#include "aes.hpp"
#include "CBBS.hpp"	
#include "cryptoTK.hpp"


#define ALLOC_FAILED (DWORD)0xB0000020L

#define SEED_LEN 32
#define BLOCK_DIM 104857600
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

	int GetIv(char iv [], int len);			//get IV from user input
	int GetKey(char key [], int len);		//get KEY from user input

	int ExecSelectedAction();				//execute the action defined by enum list

	void PrintInfo();						//prints out key and iv
	
private:

	BYTE *pbData_[3];						//random seeds

	pCBBS BBS;							//pointer to random generator class

	LPVOID iv_;							//pointer to IV
	LPVOID key_;							//pointer to KEY

	HANDLE input_file_;					//input file
	uint64_t input_file_len_;				//input file lenght

	HANDLE output_file_;					//output file
	uint64_t output_file_len_;				//input file lenght

	SYSTEM_INFO sSysInfo_;

	DWORD old_protect_value_;

	void EncryptFile();							//encrypt file
	void DecryptFile();							//decrypt file

	AesFileSelection value_;

	struct AES_ctx ctx;
};