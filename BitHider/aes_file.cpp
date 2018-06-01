#include "stdafx.h"
#include "AES_FILE.h"
#include "cryptoTK.hpp"


AesFile::AesFile(LPCWSTR path, AesFileSelection value) {

	TCHAR working_directory[MAX_STR_LEN];

	GetCurrentDirectory(MAX_STR_LEN, working_directory);

	wprintf(_T("Working Directory:%s\n"), working_directory);

	input_file_ = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);

	if (input_file_ == INVALID_HANDLE_VALUE) {
		_putws(L"Error");
	}

	/*pbData_[0] = (BYTE*)HeapAlloc(GetProcessHeap(), 0, SEED_LEN);
	pbData_[1] = (BYTE*)HeapAlloc(GetProcessHeap(), 0, SEED_LEN);
	pbData_[2] = (BYTE*)HeapAlloc(GetProcessHeap(), 0, SEED_LEN);
	*/

	pbData_[0] = (BYTE*)malloc(SEED_LEN);
	pbData_[1] = (BYTE*)malloc(SEED_LEN);
	pbData_[2] = (BYTE*)malloc(SEED_LEN);

	
	//VirtualAlloc(iv_, IV_LEN, MEM_COMMIT | MEM_RESERVE , PAGE_READWRITE);						//remove MEM_WRITE_WATCH
	//VirtualAlloc(key_, KEY_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);						//remove MEM_WRITE_WATCH
																									//VirtualAlloc(key_, KEY_LEN, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);																								//VirtualAlloc(key_, KEY_LEN, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);

	//VirtualAlloc(iv_, IV_LEN, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);						//remove MEM_WRITE_WATCH
	//VirtualAlloc(key_, KEY_LEN, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);
	
	BBS = new CBBS;
}


AesFile::~AesFile() {

	

}

int AesFile::InitGen() {
	NTSTATUS gen_random_status_code;
	int random_init_status_code;

	try {

	wprintf(L"Generating Seeds ");
	gen_random_status_code = BCryptGenRandom(NULL, pbData_[0], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	gen_random_status_code = BCryptGenRandom(NULL, pbData_[1], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	gen_random_status_code = BCryptGenRandom(NULL, pbData_[2], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (!gen_random_status_code) {
		wprintf(L"[ FAIL ]\n");
		throw ERROR_GENERATING_SEED;
	} 
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Inizializing Generator ");
	random_init_status_code = BBS->Init( (char*)pbData_[0], (char*)pbData_[1], (char*)pbData_[2], SEED_LEN);

	if (random_init_status_code) {
		wprintf(L"[ FAIL ]\n");
		throw random_init_status_code;
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	}
	catch (int x)
	{
		return x;
	}

	return 0;
}

void AesFile::GenerateIv() {
	BBS->GetRndBin(iv_, IV_LEN);
}

void AesFile::GenerateKey() {
	BBS->GetRndBin(key_, KEY_LEN);
}

void AesFile::PrintInfo() {
	wprintf(L"IV: ");
	print_hex(iv_, IV_LEN);

	wprintf(L"\nKey: ");
	print_hex(key_, KEY_LEN);
}