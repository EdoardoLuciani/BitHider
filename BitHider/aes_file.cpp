#include "stdafx.h"
#include "AES_FILE.h"
#include "cryptoTK.hpp"


AesFile::AesFile(LPCWSTR path, AesFileSelection value) {

	TCHAR working_directory[MAX_STR_LEN];

	GetCurrentDirectory(MAX_STR_LEN, working_directory);

	wprintf(_T("Working Directory:%s\n"), working_directory);

	input_file_ = CreateFileW(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);	
	
	if (input_file_ == INVALID_HANDLE_VALUE) {
		ErrorExit( (LPTSTR)L"Opening File");
	}

	for (int i = 0; i < 3; i++) {
		pbData_[i] = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);

		if ( pbData_[i] == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"Problem");
		}
	}
	
	iv_ = VirtualAlloc(NULL, IV_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	key_ = VirtualAlloc(NULL, IV_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (iv_ == NULL || key_ == NULL) {
		ErrorExit((LPTSTR)L"VirtualAlloc");
	}
	
	BBS = new CBBS;
}


AesFile::~AesFile() {

	

}

int AesFile::InitGen() {
	NTSTATUS gen_random_status_code;
	int random_init_status_code;

	try {
	//Starting Seed Generation

	for (int i = 0; i < 3; i++) {
	wprintf(L"Generating Seed #%d ", i);
	gen_random_status_code = BCryptGenRandom(NULL, pbData_[i], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if ( gen_random_status_code != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		throw gen_random_status_code;
		} 
	else {
		wprintf(L"[ OK ]\n");
		} 
	}

	//Generator Inizialization

	wprintf(L"Inizializing Generator ");
	random_init_status_code = BBS->Init( (char*)pbData_[0], (char*)pbData_[1], (char*)pbData_[2], SEED_LEN);

	if (random_init_status_code) {
		wprintf(L"[ FAIL ]\n");
		throw (DWORD)random_init_status_code;
		}
	else {
		wprintf(L"[ OK ]\n");
		}

	}
	catch (DWORD x) {
		SetLastError(x);
		ErrorExit((LPTSTR)L"Problem");
	}

	return 0;
}

void AesFile::GenerateIv() {
	BBS->GetRndBin((uint8_t*)iv_, IV_LEN);
}

void AesFile::GenerateKey() {
	BBS->GetRndBin((uint8_t*)key_, KEY_LEN);
}

void AesFile::PrintInfo() {

	wprintf(L"\n\nIV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);

	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);

	for (int i = 0; i < 3; i++) {
		wprintf(L"Seed: ");
		PrintHex(pbData_[i], KEY_LEN);
	}
	
}