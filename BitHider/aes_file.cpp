#include "stdafx.h"
#include "AES_FILE.h"
#include "cryptoTK.hpp"


AesFile::AesFile(LPCWSTR input_file_path, AesFileSelection value) {
	TCHAR output_file_path[MAX_STR_LEN];

	value_ = value;

	GetModuleFileNameW(NULL, output_file_path, MAX_STR_LEN);
	PathCchRemoveFileSpec(output_file_path, MAX_STR_LEN);

	if (value_ == Encrypt) {
		StringCchCatW(output_file_path, MAX_STR_LEN, (LPCWSTR)L"\\encrypted_files\\");
	}
	else {
		StringCchCatW(output_file_path, MAX_STR_LEN, (LPCWSTR)L"\\decrypted_files\\");
	}
	StringCchCatW(output_file_path, MAX_STR_LEN, PathFindFileName(input_file_path));

	wprintf(_T("Input File: %s\n"), input_file_path);
	wprintf(_T("Destination Path: %s\n"), output_file_path);

	wprintf(_T("Path address: %p\n"), &output_file_path[0]);

	wprintf(L"\n\n");

	GetSystemInfo(&sSysInfo_);

	wprintf(L"Opening Input File ");
	input_file_ = CreateFileW(input_file_path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (input_file_ == INVALID_HANDLE_VALUE) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit( (LPTSTR)L"CreateFileW");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Opening Output File ");
	output_file_ = CreateFileW(output_file_path, GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (input_file_ == INVALID_HANDLE_VALUE) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"CreateFileW");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	BBS = new CBBS;

	
	for (int i = 0; i < 3; i++) {
		wprintf(L"Allocating Memory #%d ", i);
		pbData_[i] = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);

		if ( pbData_[i] == NULL) {
			wprintf(L"[ FAIL ]\n");
			SetLastError(ALLOC_FAILED);
			ErrorExit((LPTSTR)L"HeapAlloc");
			}
		else {
			wprintf(L"[ OK ]\n");
		}
	}
	
	wprintf(L"Allocating Memory in Virtual Space ");
	iv_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	key_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (iv_ == NULL || key_ == NULL) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Locking Virtual Space ");
	if (!VirtualLock(iv_, sSysInfo_.dwPageSize) || !VirtualLock(iv_, sSysInfo_.dwPageSize)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualLock");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Inizializing Algorithm ");
	error = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_AES_ALGORITHM, NULL, NULL);
	if (error != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(OPEN_ALG_FAILED);
		ErrorExit((LPTSTR)L"BCryptOpenAlgorithProvider");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Setting algorithm propriety");
	error = BCryptSetProperty(algorithm_, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (error != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(SET_CHAIN_MODE_FAILED);
		ErrorExit((LPTSTR)L"BCryptSetProperty");
	}
	else {
		wprintf(L"[ OK ]\n");
	}


	wprintf(L"\n");
}


AesFile::~AesFile() {

	wprintf(L"Closing Algorithm ");

	error = BCryptCloseAlgorithmProvider(&algorithm_, 0);
	if ( error!= 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error);
		ErrorExit((LPTSTR)L"BCryptCloseAlgorithmProvider");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	SecureZeroMemory(key_, KEY_LEN);
	SecureZeroMemory(iv_, IV_LEN);

	wprintf(L"Freeing Memory ");
	if (!VirtualFree(key_, 0, MEM_RELEASE) | !VirtualFree(iv_, 0, MEM_RELEASE)) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(DEALLOC_FAILED);
		ErrorExit((LPTSTR)L"VirtualFree");
	}
	
	CloseHandle(input_file_);
	CloseHandle(output_file_);
}

int AesFile::InitGen() {
	int random_init_status_code;

	try {
	//Starting Seed Generation

	for (int i = 0; i < 3; i++) {
	wprintf(L"Generating Seed #%d ", i);
	error = BCryptGenRandom(NULL, pbData_[i], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (error != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		throw error;
		} 
	else {
		wprintf(L"[ OK ]\n");
		} 
	}

	//Generator Inizialization

	wprintf(L"Inizializing Generator ");
	random_init_status_code = BBS->Init( (char*)pbData_[0], (char*)pbData_[1], (char*)pbData_[2], SEED_LEN);

	for (int i = 0; i < 3; i++) {
		SecureZeroMemory(pbData_[i], SEED_LEN);
		HeapFree(GetProcessHeap(), 0, pbData_[i]);
	}
	

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
	wprintf(L"\n");
	return 0;
}

void AesFile::GenerateIv() {
	wprintf(L"IV Generation ");
	BBS->GetRndBin((uint8_t*)iv_, IV_LEN);
	wprintf(L"[ OK ]\n");

	wprintf(L"IV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);


	wprintf(L"Memory Locking ");
	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_NOACCESS, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}
	wprintf(L"\n");
}

void AesFile::GenerateKey() {
	wprintf(L"Key Generation ");
	BBS->GetRndBin((uint8_t*)key_, KEY_LEN);
	wprintf(L"[ OK ]\n");

	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);

	wprintf(L"Memory Locking ");
	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_NOACCESS, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}
	wprintf(L"\n");
}




int AesFile::ExecSelectedAction() {

	BBS->Clear();

	if (value_ == Encrypt) {
		EncryptFileC();
	}
	else {
		DecryptFileC();
	}
	return 0;
}


void AesFile::EncryptFileC() {

	LARGE_INTEGER offset;
	LPVOID data_input;
	LPVOID data_output;
	uint64_t blocks;
	int left_over_bytes_input,left_over_bytes_output;
	ULONG dummy;

	BCRYPT_KEY_HANDLE key;

	wprintf(L"Memory Unlocking ");
	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Memory Unlocking ");
	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	GetFileSizeEx(input_file_, &offset);
	blocks = offset.QuadPart / BLOCK_DIM;
	left_over_bytes_input = offset.QuadPart % BLOCK_DIM;

	left_over_bytes_output = left_over_bytes_input;
	while (left_over_bytes_output % 16 != 0) {
		left_over_bytes_output++;
	}

	if (blocks) {
		wprintf(L"Blocks: %llu\n", blocks);
	}

	wprintf(L"Input File Left Over Bytes: %d Bytes\n", left_over_bytes_input);
	wprintf(L"Input File Dimension: %lld Bytes\n\n", offset.QuadPart);

	wprintf(L"Output File Left Over Bytes: %d Bytes\n", left_over_bytes_output);
	wprintf(L"Output File Dimension: %lld Bytes\n\n", blocks*BLOCK_DIM + left_over_bytes_output);

	wprintf(L"Allocating Memory ");
	data_input = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	data_output = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	if (data_input == NULL || data_output == NULL ) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Generating Key ");
	error = BCryptGenerateSymmetricKey(algorithm_, &key, NULL, NULL, (PUCHAR)key_, KEY_LEN, 0);
	if (error != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error);
		ErrorExit((LPTSTR)L"BCryptGenerateSymmetricKey");
	}
	else {
		wprintf(L"[ OK ]\n");
	}


	for (uint64_t i = 0; i < blocks; i++) {
		
		if ( !ReadFile(input_file_, data_input, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		if (BCryptEncrypt(key, (PUCHAR)data_input, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, BLOCK_DIM, NULL, BCRYPT_PAD_NONE) != 0x00000000) {
			SetLastError(ENCRYPT_DECRYPT_FAILED);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}
	}

	SecureZeroMemory(data_input, BLOCK_DIM);
	SecureZeroMemory(data_output, BLOCK_DIM);

	wprintf(L"Reallocating Memory ");
	data_input = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_input, left_over_bytes_output);
	data_output = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_output, left_over_bytes_output);
	if (data_input == NULL || data_output == NULL) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapReAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	if (!ReadFile(input_file_, data_input, left_over_bytes_input, NULL, NULL)) {
		ErrorExit((LPTSTR)L"ReadFile");
	}

	error = 0;

	error = BCryptEncrypt(key, (PUCHAR)data_input, left_over_bytes_output, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, left_over_bytes_output, &dummy, 0);
	if (error != 0x00000000) {
		SetLastError(error);
		ErrorExit((LPTSTR)L"BCryptEncrypto");
	}

	if (!WriteFile(output_file_, data_output, left_over_bytes_output, NULL, NULL)) {
		ErrorExit((LPTSTR)L"WriteFile");
	}
	
	SecureZeroMemory(data_input, left_over_bytes_output);
	SecureZeroMemory(data_output, left_over_bytes_output);

	HeapFree(GetProcessHeap(), 0, data_input);
	HeapFree(GetProcessHeap(), 0, data_output);

	BCryptDestroyKey(key);

	wprintf(L"\n");
}

void AesFile::DecryptFileC() {

	LARGE_INTEGER offset;
	LPVOID data;

	GetFileSizeEx(input_file_, &offset);

	wprintf(L"File Dimension %lld Bytes", offset.QuadPart);

	data = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);





	//ReadFile(input_file_,data)
}


void AesFile::PrintInfo() {

	wprintf(L"\n\nIV Address 0x%lp\n", iv_);

	wprintf(L"Key Address 0x%lp\n", key_);

	wprintf(L"IV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);

	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);


	for (int i = 0; i < 3; i++) {
		wprintf(L"Seed #%d Address: 0x%lp\n", i, pbData_[i]);
	}

	for (int i = 0; i < 3; i++) {
		wprintf(L"Seed #%d: ",i);
		PrintHex(pbData_[i], KEY_LEN);
	}
}