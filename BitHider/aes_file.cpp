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
	StringCchCatW(output_file_path, MAX_STR_LEN, PathFindFileNameW(input_file_path));

	GetSystemInfo(&sSysInfo_);

	wprintf(_T("Input File: %s\n"), input_file_path);
	wprintf(_T("Output File Destination Path: %s\n"), output_file_path);

	wprintf(L"\n\n");

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
	output_file_ = CreateFileW(output_file_path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (output_file_ == INVALID_HANDLE_VALUE) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"CreateFileW");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Allocating Memory in Virtual Space ");
	iv_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	key_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if ( (iv_ == NULL) || (key_ == NULL) ) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}
	
	wprintf(L"\nIV Address 0x%lp\n", iv_);

	wprintf(L"Key Address 0x%lp\n", key_);

	wprintf(L"Locking Virtual Space ");
	bool success;
	success = VirtualLock(key_, sSysInfo_.dwPageSize);
	success = VirtualLock(iv_, sSysInfo_.dwPageSize);
	if (!success) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualLock");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Inizializing Algorithm ");
	error_ = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_AES_ALGORITHM, NULL, NULL);
	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptOpenAlgorithProvider");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Setting Algorithm Propriety ");
	error_ = BCryptSetProperty(algorithm_, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptSetProperty");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"\n");
}


AesFile::~AesFile() {

	SecureZeroMemory(key_, KEY_LEN);
	SecureZeroMemory(iv_, IV_LEN);

	wprintf(L"Unlocking Memory ");
	if ( (!VirtualUnlock(key_, sSysInfo_.dwPageSize)) || (!VirtualUnlock(iv_, sSysInfo_.dwPageSize)) ) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualUnlock");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Freeing Memory ");
	if (  (!VirtualFree(key_, 0, MEM_RELEASE)) || (!VirtualFree(iv_, 0, MEM_RELEASE)) ) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualFree");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Closing Algorithm ");
	error_ = BCryptCloseAlgorithmProvider(algorithm_, 0);
	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptCloseAlgorithmProvider");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	CloseHandle(input_file_);
	CloseHandle(output_file_);
}


int AesFile::InitGen() {

	int random_init_status_code;

	//Starting Seed Generation

	for (int i = 0; i < 3; i++) {

	wprintf(L"Allocating Memory #%d for Seed", i);
	pbData_[i] = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);
	if (pbData_[i] == NULL) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}


	wprintf(L"Generating Seed #%d ", i);
	error_ = BCryptGenRandom(NULL, pbData_[i], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenRandom");
	} 
	else {
		wprintf(L"[ OK ]\n");
	}

	}

	//Generator Inizialization

	BBS = new CBBS;

	wprintf(L"Inizializing Generator ");
	random_init_status_code = BBS->Init( (char*)pbData_[0], (char*)pbData_[1], (char*)pbData_[2], SEED_LEN);

	if (random_init_status_code) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(random_init_status_code);
		ErrorExit((LPTSTR)L"BBS Init");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	for (int i = 0; i < 3; i++) {
		SecureZeroMemory(pbData_[i], SEED_LEN);
		HeapFree(GetProcessHeap(), 0, pbData_[i]);
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


	wprintf(L"Memory Protecting ");
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

	wprintf(L"Memory Protecting ");
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
	INT blocks;
	INT left_over_bytes_input,left_over_bytes_output;
	ULONG dummy;

	wprintf(L"IV Memory Unprotecting ");
	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	if (!VirtualLock(iv_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}


	wprintf(L"Key Memory Unprotecting ");
	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		wprintf(L"[ FAIL ]\n");
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	if (!VirtualLock(key_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}

	GetFileSizeEx(input_file_, &offset);
	blocks = offset.QuadPart / BLOCK_DIM;
	left_over_bytes_input = offset.QuadPart % BLOCK_DIM;

	wprintf(L"Generating Key ");
	error_ = BCryptGenerateSymmetricKey(algorithm_, &key_handle_, NULL, NULL, (PUCHAR)key_, KEY_LEN, 0);
	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenerateSymmetricKey");
	}
	else {
		wprintf(L"[ OK ]\n");
	}


	wprintf(L"Allocating Memory ");
	data_input = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	data_output = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	if (data_input == NULL || data_output == NULL) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"Encryption \n");

	for (uint64_t i = 0; i < blocks; i++) {
		
		if ( !ReadFile(input_file_, data_input, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		error_ = BCryptEncrypt(key_handle_, (PUCHAR)data_input, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, BLOCK_DIM, NULL, BCRYPT_PAD_NONE);
		if (error_ != 0x00000000) {
			SetLastError(error_);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}
	}

	SecureZeroMemory(data_input, BLOCK_DIM);
	SecureZeroMemory(data_output, BLOCK_DIM);

	data_input = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_input, left_over_bytes_input);
	left_over_bytes_output = AnsiX293ForcePad(GetProcessHeap(), data_input, left_over_bytes_input, 16);
	
	data_output = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_output, left_over_bytes_output);


	if (data_input == NULL || data_output == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapReAlloc");
	}

	if (!ReadFile(input_file_, data_input, left_over_bytes_input, NULL, NULL)) {
		ErrorExit((LPTSTR)L"ReadFile");
	}

	error_ = BCryptEncrypt(key_handle_, (PUCHAR)data_input, left_over_bytes_output, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, left_over_bytes_output, &dummy, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptEncrypt");
	}

	if (!WriteFile(output_file_, data_output, left_over_bytes_output, NULL, NULL)) {
		ErrorExit((LPTSTR)L"WriteFile");
	}
	
	SecureZeroMemory(data_input, left_over_bytes_output);
	SecureZeroMemory(data_output, left_over_bytes_output);

	HeapFree(GetProcessHeap(), 0, data_input);
	HeapFree(GetProcessHeap(), 0, data_output);

	wprintf(L"END Encryption \n");


	if (blocks) {
		wprintf(L"Blocks: %llu\n", blocks);
		wprintf(L"Input File Left Over Bytes: %d Bytes\n", left_over_bytes_input);
		wprintf(L"Input File Dimension: %lld Bytes\n\n", offset.QuadPart);

		wprintf(L"Output File Left Over Bytes: %d Bytes\n", left_over_bytes_output);
		wprintf(L"Output File Dimension: %lld Bytes\n\n", blocks*BLOCK_DIM + left_over_bytes_output);
	}
	else {
		wprintf(L"Input File Dimension: %lld Bytes\n", offset.QuadPart);
		wprintf(L"Output File Dimension: %lld Bytes\n", left_over_bytes_output);
	}


	wprintf(L"Destroying key ");
	error_ = BCryptDestroyKey(key_handle_);
	if (error_ != 0x00000000) {
		wprintf(L"[ FAIL ]\n");
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptDestoryKey");
	}
	else {
		wprintf(L"[ OK ]\n");
	}

	wprintf(L"\n");
}


void AesFile::DecryptFileC() {

	LARGE_INTEGER offset;
	LPVOID data_input;
	LPVOID data_output;
	INT blocks;
	INT left_over_bytes_input, left_over_bytes_output;
	ULONG dummy;

	GetFileSizeEx(input_file_, &offset);

	wprintf(L"File Dimension %lld Bytes", offset.QuadPart);

	//data = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);


	//ReadFile(input_file_,data)
}


void AesFile::PrintInfo() {

	wprintf(L"\n\nIV Address 0x%lp\n", iv_);

	wprintf(L"Key Address 0x%lp\n", key_);

	wprintf(L"IV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);

	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);
}