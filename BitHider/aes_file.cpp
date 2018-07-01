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

	input_file_ = CreateFileW(input_file_path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (input_file_ == INVALID_HANDLE_VALUE) {
		ErrorExit( (LPTSTR)L"CreateFileW");
	}

	output_file_ = CreateFileW(output_file_path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (output_file_ == INVALID_HANDLE_VALUE) {
		ErrorExit((LPTSTR)L"CreateFileW");
	}

	iv_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	key_ = VirtualAlloc(NULL, sSysInfo_.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if ( (iv_ == NULL) || (key_ == NULL) ) {
		ErrorExit((LPTSTR)L"VirtualAlloc");
	}

	bool success;
	success = VirtualLock(key_, sSysInfo_.dwPageSize);
	success = VirtualLock(iv_, sSysInfo_.dwPageSize);
	if (!success) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}

	error_ = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_AES_ALGORITHM, NULL, NULL);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptOpenAlgorithProvider");
	}

	error_ = BCryptSetProperty(algorithm_, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptSetProperty");
	}

	hIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hIn == INVALID_HANDLE_VALUE) {
		ErrorExit((LPTSTR)L"CreateConsoleInputHandle");
	}

	hOut = CreateConsoleScreenBuffer(GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CONSOLE_TEXTMODE_BUFFER, NULL);
	if (hOut == INVALID_HANDLE_VALUE) {
		ErrorExit((LPTSTR)L"CreateConsoleOutputHandle");
	}

	GetConsoleMode(hIn, &input_console_mode_);
	input_console_mode_ = 0;
	input_console_mode_ = ENABLE_EXTENDED_FLAGS | ENABLE_INSERT_MODE | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE | ENABLE_VIRTUAL_TERMINAL_INPUT;
	SetConsoleMode(hIn, input_console_mode_);

	wprintf(L"\n");

}


AesFile::~AesFile() {

	SecureZeroMemory(key_, KEY_LEN);
	SecureZeroMemory(iv_, IV_LEN);

	if ( (!VirtualUnlock(key_, sSysInfo_.dwPageSize)) || (!VirtualUnlock(iv_, sSysInfo_.dwPageSize)) ) {
		ErrorExit((LPTSTR)L"VirtualUnlock");
	}

	if (  (!VirtualFree(key_, 0, MEM_RELEASE)) || (!VirtualFree(iv_, 0, MEM_RELEASE)) ) {
		ErrorExit((LPTSTR)L"VirtualFree");
	}

	error_ = BCryptCloseAlgorithmProvider(algorithm_, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptCloseAlgorithmProvider");
	}

	CloseHandle(input_file_);
	CloseHandle(output_file_);
	
	CloseHandle(hIn);
	CloseHandle(hOut);
}


int AesFile::InitGen() {

	BYTE *pbData_[3];
	int random_init_status_code;

	//Starting Seed Generation

	for (int i = 0; i < 3; i++) {

	pbData_[i] = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, SEED_LEN);
	if (pbData_[i] == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}

	error_ = BCryptGenRandom(NULL, pbData_[i], SEED_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenRandom");
	} 

	}

	//Generator Inizialization

	BBS = new CBBS;

	random_init_status_code = BBS->Init( (char*)pbData_[0], (char*)pbData_[1], (char*)pbData_[2], SEED_LEN);

	if (random_init_status_code) {
		SetLastError(random_init_status_code);
		ErrorExit((LPTSTR)L"BBS Init");
	}

	for (int i = 0; i < 3; i++) {
		SecureZeroMemory(pbData_[i], SEED_LEN);
		HeapFree(GetProcessHeap(), 0, pbData_[i]);
	}

	return 0;
}


void AesFile::GenerateIv() {
	BBS->GetRndBin((uint8_t*)iv_, IV_LEN);

	SetColor(GetStdHandle(STD_OUTPUT_HANDLE),10);
	wprintf(L"IV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);
	SetColor(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_NOACCESS, &old_protect_value_)) {
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	wprintf(L"\n");
}


void AesFile::GenerateKey() {
	BBS->GetRndBin((uint8_t*)key_, KEY_LEN);

	SetColor(GetStdHandle(STD_OUTPUT_HANDLE), 10);
	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);
	SetColor(GetStdHandle(STD_OUTPUT_HANDLE), 15);

	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_NOACCESS, &old_protect_value_)) {
		ErrorExit((LPTSTR)L"VirtualProtect");
	}
	wprintf(L"\n");
}

void AesFile::GetIv() {

	LPVOID iv_string;

	iv_string = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IV_LEN*2);
	SetConsoleActiveScreenBuffer(hOut);

	do {
	WriteConsoleA(hOut, "Insert IV (32 characters in HEX) Data will be displayed after, if this message repeats the previous input is not valid: ", lstrlenA("Insert IV (32 characters in HEX) Data will be displayed after, if this message repeats the previous input is not valid: "), &cWritten, NULL);
	ReadConsoleA(hIn, iv_string, IV_LEN * 2, &cRead, NULL);
	FlushConsoleInputBuffer(hIn);
	NewLine(hOut);
	} while ((CheckHexString(iv_string, IV_LEN * 2) != 0) || (cRead != IV_LEN * 2)   );


	WriteConsoleA(hOut, "Data will be displayed for 10 seconds!!!", lstrlenA("Data will be displayed for 10 seconds!!!"), &cWritten, NULL);
	NewLine(hOut);
	WriteConsoleA(hOut, iv_string, IV_LEN * 2, &cWritten, NULL);
	Sleep(8000);

	HeapFree(GetProcessHeap(), NULL, iv_string);
	ClearOutputBuffer(hOut);
	HexStringToHexValue((char*)iv_string, (uint8_t*)iv_, IV_LEN * 2);

	SetConsoleActiveScreenBuffer(GetStdHandle(STD_OUTPUT_HANDLE));
}

void AesFile::GetKey() {

	LPVOID key_string;

	key_string = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEY_LEN * 2);

	SetConsoleActiveScreenBuffer(hOut);

	do {
		WriteConsoleA(hOut, "Insert KEY (64 characters in HEX) Data will be displayed after, if this message repeats the previous input is not valid: ", lstrlenA("Insert KEY (64 characters in HEX) Data will be displayed after, if this message repeats the previous input is not valid: "), &cWritten, NULL);
		FlushConsoleInputBuffer(hIn);
		ReadConsoleA(hIn, key_string, KEY_LEN * 2, &cRead, NULL);
		NewLine(hOut);
	} while ((CheckHexString(key_string, KEY_LEN * 2) != 0) || (cRead != KEY_LEN * 2));

	WriteConsoleA(hOut, "Data will be displayed for 10 seconds!!!", lstrlenA("Data will be displayed for 10 seconds!!!"), &cWritten, NULL);
	NewLine(hOut);
	WriteConsoleA(hOut, key_string, KEY_LEN * 2, &cWritten, NULL);
	Sleep(8000);

	HeapFree(GetProcessHeap(), NULL, key_string);
	ClearOutputBuffer(hOut);
	HexStringToHexValue((char*)key_string, (uint8_t*)key_, KEY_LEN * 2);

	SetConsoleActiveScreenBuffer(GetStdHandle(STD_OUTPUT_HANDLE));
}


int AesFile::ExecSelectedAction() {

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

	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		ErrorExit((LPTSTR)L"VirtualProtect");
	}


	if (!VirtualLock(iv_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}

	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		ErrorExit((LPTSTR)L"VirtualProtect");
	}


	if (!VirtualLock(key_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}

	GetFileSizeEx(input_file_, &offset);
	blocks = offset.QuadPart / BLOCK_DIM;
	left_over_bytes_input = offset.QuadPart % BLOCK_DIM;

	error_ = BCryptGenerateSymmetricKey(algorithm_, &key_handle_, NULL, NULL, (PUCHAR)key_, KEY_LEN, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenerateSymmetricKey");
	}


	data_input = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	data_output = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	if (data_input == NULL || data_output == NULL) {;
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}

	wprintf(L"Encryption Started\n");

	int dwElapsed = 0;
	DOUBLE seconds = 0;
	DOUBLE speed = 0;
	DWORD start = 0;
	DWORD end = 0;
	DOUBLE medium_speed = 0;

	for (uint64_t i = 1; i <= blocks; i++) {
		start = GetTickCount();

		wprintf(L"Encrypting Block Number: %d\\%d  %.2f %% %lf MB/s \n", i, blocks, 100.0*i / blocks, speed);
		
		if ( !ReadFile(input_file_, data_input, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		error_ = BCryptEncrypt(key_handle_, (PUCHAR)data_input, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, BLOCK_DIM, &dummy, 0);
		if (error_ != 0x00000000) {
			SetLastError(error_);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}

		end = GetTickCount();
		dwElapsed = start - end;
		seconds = abs(dwElapsed) / 1000.0;
		speed = 104.8576 / seconds;
		medium_speed = (medium_speed + speed) / (i);
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
		wprintf(L"\nBlocks: %llu\n", blocks);
		wprintf(L"Input File Left Over Bytes: %d Bytes\n", left_over_bytes_input);
		wprintf(L"Input File Dimension: %lld Bytes\n\n", offset.QuadPart);

		wprintf(L"Output File Left Over Bytes: %d Bytes\n", left_over_bytes_output);
		wprintf(L"Output File Dimension: %lld Bytes\n\n", blocks*BLOCK_DIM + left_over_bytes_output);
	}
	else {
		wprintf(L"Input File Dimension: %lld Bytes\n", offset.QuadPart);
		wprintf(L"Output File Dimension: %lld Bytes\n", left_over_bytes_output);
	}


	error_ = BCryptDestroyKey(key_handle_);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptDestoryKey");
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

	if (!VirtualProtect(iv_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {

		ErrorExit((LPTSTR)L"VirtualProtect");
	}


	if (!VirtualLock(iv_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}


	if (!VirtualProtect(key_, sSysInfo_.dwPageSize, PAGE_READWRITE, &old_protect_value_)) {
		ErrorExit((LPTSTR)L"VirtualProtect");
	}


	if (!VirtualLock(key_, sSysInfo_.dwPageSize)) {
		ErrorExit((LPTSTR)L"VirtualLock");
	}

	GetFileSizeEx(input_file_, &offset);
	blocks = offset.QuadPart / BLOCK_DIM;
	left_over_bytes_input = offset.QuadPart % BLOCK_DIM;

	error_ = BCryptGenerateSymmetricKey(algorithm_, &key_handle_, NULL, NULL, (PUCHAR)key_, KEY_LEN, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenerateSymmetricKey");
	}



	data_input = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	data_output = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	if (data_input == NULL || data_output == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}

	wprintf(L"Decryption Started\n");

	int dwElapsed = 0;
	DOUBLE seconds = 0;
	DOUBLE speed = 0;
	DWORD start = 0;
	DWORD end = 0;
	DOUBLE medium_speed = 0;

	for (uint64_t i = 1; i <= blocks; i++) {
		start = GetTickCount();

		wprintf(L"Decrypting Block Number: %d\\%d  %.2f %% %lf MB/s \n", i, blocks, 100.0*i / blocks, speed);

		if (!ReadFile(input_file_, data_input, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		error_ = BCryptDecrypt(key_handle_, (PUCHAR)data_input, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, BLOCK_DIM, &dummy, 0);
		if (error_ != 0x00000000) {
			SetLastError(error_);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}

		end = GetTickCount();
		dwElapsed = start - end;
		seconds = abs(dwElapsed) / 1000.0;
		speed = 104.8576 / seconds;
		//medium_speed = (medium_speed + speed) / (i);
	}

	SecureZeroMemory(data_input, BLOCK_DIM);
	SecureZeroMemory(data_output, BLOCK_DIM);

	data_input = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_input, left_over_bytes_input);
	data_output = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_output, left_over_bytes_input);


	if (data_input == NULL || data_output == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapReAlloc");
	}

	if (!ReadFile(input_file_, data_input, left_over_bytes_input, NULL, NULL)) {
		ErrorExit((LPTSTR)L"ReadFile");
	}


	error_ = BCryptDecrypt(key_handle_, (PUCHAR)data_input, left_over_bytes_input, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output, left_over_bytes_input, &dummy, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptEncrypt");
	}

	left_over_bytes_output = AnsiX293ForceReversePad(GetProcessHeap(), data_output, left_over_bytes_input);


	if (!WriteFile(output_file_, data_output, left_over_bytes_output, NULL, NULL)) {
		ErrorExit((LPTSTR)L"WriteFile");
	}

	SecureZeroMemory(data_input, left_over_bytes_input);
	SecureZeroMemory(data_output, left_over_bytes_output);

	HeapFree(GetProcessHeap(), 0, data_input);
	HeapFree(GetProcessHeap(), 0, data_output);

	wprintf(L"END Decryption \n");


	if (blocks) {
		wprintf(L"\nBlocks: %llu\n", blocks);
		wprintf(L"Input File Left Over Bytes: %d Bytes\n", left_over_bytes_input);
		wprintf(L"Input File Dimension: %lld Bytes\n\n", offset.QuadPart);

		wprintf(L"Output File Left Over Bytes: %d Bytes\n", left_over_bytes_output);
		wprintf(L"Output File Dimension: %lld Bytes\n\n", blocks*BLOCK_DIM + left_over_bytes_output);
	}
	else {
		wprintf(L"Input File Dimension: %lld Bytes\n", offset.QuadPart);
		wprintf(L"Output File Dimension: %lld Bytes\n", left_over_bytes_output);
	}


	error_ = BCryptDestroyKey(key_handle_);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptDestoryKey");
	}

}


void AesFile::PrintInfo() {

	wprintf(L"IV: ");
	PrintHex((uint8_t*)iv_, IV_LEN);

	wprintf(L"Key: ");
	PrintHex((uint8_t*)key_, KEY_LEN);
}