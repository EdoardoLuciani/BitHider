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

	TCHAR path[MAX_STR_LEN] = { NULL };
	OPENFILENAME ofn;       // common dialog box structure
	HWND hwnd = NULL;              // owner window
	HANDLE hf = NULL;              // file handle

	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = path;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(path);
	ofn.lpstrFilter = NULL;
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = L"C:";
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	//display the open dialog box.

	GetOpenFileName(&ofn);

 	AesFile Data(path,Encrypt);

	Data.InitGen();

	Data.GenerateIv();
	Data.GenerateKey();

	Data.ExecSelectedAction();

	Data.PrintInfo();

	system("PAUSE");
	Data.~AesFile();
	
	
    return 0;
}

