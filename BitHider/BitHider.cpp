// CryptoMaster.cpp : Defines the entry point for the console application.


/* TODO 

Add GPL as license

*/


#include "stdafx.h"					//Precompiled Header

#include "CBBS.hpp"					//Blum Blum Shub Random Number Generator
#include "cryptoTK.hpp"				//Crypto Tool Kit
#include "aes.hpp"					//AES algorithm library
#include "aes_file.h"







int main() {
	int error;

 	AesFile Data(L"file.txt",Encrypt);

	error = Data.InitGen();
	if ( error != 0) {
		wprintf( L"Error Inizializing: %d\n", error);
	}

	Data.GenerateIv();
	Data.GenerateKey();

	

	Data.PrintInfo();

	system("PAUSE");
    return 0;
}

