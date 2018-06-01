#pragma once

#include "stdafx.h"
#include "aes.hpp"
#include "CBBS.hpp"	
#include "cryptoTK.hpp"

#define ERROR_GENERATING_SEED 200



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

	BYTE *iv_;							//pointer to IV
	BYTE *key_;							//pointer to KEY

	HANDLE input_file_;					//input file
	uint64_t input_file_len_;				//input file lenght

	HANDLE output_file_;					//output file
	uint64_t output_file_len_;				//input file lenght

	void EncryptFile();							//encrypt file
	void DecryptFile();							//decrypt file

	AesFileSelection value_;

	struct AES_ctx ctx;

};