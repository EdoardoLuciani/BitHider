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

	error_ = BCryptDestroyKey(key_handle_);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptDestoryKey");
	}


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

	GetFileSizeEx(input_file_, &offset_);
	blocks_ = offset_.QuadPart / BLOCK_DIM;
	left_over_bytes_input_ = offset_.QuadPart % BLOCK_DIM;

	if (blocks_) {
	data_input_ = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	data_output_ = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, BLOCK_DIM);
	}
	else {
	data_input_ = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, 10);
	data_output_ = (BYTE*)HeapAlloc(GetProcessHeap(), NULL, 10);
	}
	
	if (data_input_ == NULL || data_output_ == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapAlloc");
	}

	error_ = BCryptGenerateSymmetricKey(algorithm_, &key_handle_, NULL, NULL, (PUCHAR)key_, KEY_LEN, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptGenerateSymmetricKey");
	}


	if (value_ == Encrypt) {
		EncryptFileC();
	}
	else {
		DecryptFileC();
	}
	return 0;
}


void AesFile::EncryptFileC() {

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

	wprintf(L"Encryption Started\n");

	int dwElapsed = 0;
	DOUBLE seconds = 0;
	DOUBLE speed = 0;
	DWORD start = 0;
	DWORD end = 0;
	DOUBLE medium_speed = 0;

	for (uint64_t i = 1; i <= blocks_; i++) {
		start = GetTickCount();

		wprintf(L"Encrypting Block Number: %d\\%d  %.2f %% %lf MB/s \n", i, blocks_, 100.0*i / blocks_, speed);
		
		if ( !ReadFile(input_file_, data_input_, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		error_ = BCryptEncrypt(key_handle_, (PUCHAR)data_input_, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output_, BLOCK_DIM, &dummy, 0);
		if (error_ != 0x00000000) {
			SetLastError(error_);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output_, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}

		end = GetTickCount();
		dwElapsed = start - end;
		seconds = abs(dwElapsed) / 1000.0;
		speed = 104.8576 / seconds;
		medium_speed = (medium_speed + speed) / (i);
	}

	SecureZeroMemory(data_input_, BLOCK_DIM);
	SecureZeroMemory(data_output_, BLOCK_DIM);

	data_input_ = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_input_, left_over_bytes_input_);
	left_over_bytes_output_ = AnsiX293ForcePad(GetProcessHeap(), data_input_, left_over_bytes_input_, 16);
	
	data_output_ = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_output_, left_over_bytes_output_);

	if (data_input_ == NULL || data_output_ == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapReAlloc");
	}

	if (!ReadFile(input_file_, data_input_, left_over_bytes_input_, NULL, NULL)) {
		ErrorExit((LPTSTR)L"ReadFile");
	}

	error_ = BCryptEncrypt(key_handle_, (PUCHAR)data_input_, left_over_bytes_output_, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output_, left_over_bytes_output_, &dummy, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptEncrypt");
	}

	if (!WriteFile(output_file_, data_output_, left_over_bytes_output_, NULL, NULL)) {
		ErrorExit((LPTSTR)L"WriteFile");
	}
	
	SecureZeroMemory(data_input_, left_over_bytes_output_);
	SecureZeroMemory(data_output_, left_over_bytes_output_);

	HeapFree(GetProcessHeap(), 0, data_input_);
	HeapFree(GetProcessHeap(), 0, data_output_);

	wprintf(L"END Encryption\n\n");
}


void AesFile::DecryptFileC() {

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

	wprintf(L"Decryption Started\n");

	int dwElapsed = 0;
	DOUBLE seconds = 0;
	DOUBLE speed = 0;
	DWORD start = 0;
	DWORD end = 0;
	DOUBLE medium_speed = 0;

	for (uint64_t i = 1; i <= blocks_; i++) {
		start = GetTickCount();

		wprintf(L"Decrypting Block Number: %d\\%d  %.2f %% %lf MB/s \n", i, blocks_, 100.0*i / blocks_, speed);

		if (!ReadFile(input_file_, data_input_, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"ReadFile");
		}

		error_ = BCryptDecrypt(key_handle_, (PUCHAR)data_input_, BLOCK_DIM, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output_, BLOCK_DIM, &dummy, 0);
		if (error_ != 0x00000000) {
			SetLastError(error_);
			ErrorExit((LPTSTR)L"BCryptEncrypt");
		}

		if (!WriteFile(output_file_, data_output_, BLOCK_DIM, NULL, NULL)) {
			ErrorExit((LPTSTR)L"WriteFile");
		}

		end = GetTickCount();
		dwElapsed = start - end;
		seconds = abs(dwElapsed) / 1000.0;
		speed = 104.8576 / seconds;
		//medium_speed = (medium_speed + speed) / (i);
	}

	SecureZeroMemory(data_input_, BLOCK_DIM);
	SecureZeroMemory(data_output_, BLOCK_DIM);

	data_input_ = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_input_, left_over_bytes_input_);
	data_output_ = (BYTE*)HeapReAlloc(GetProcessHeap(), NULL, data_output_, left_over_bytes_input_);


	if (data_input_ == NULL || data_output_ == NULL) {
		SetLastError(ALLOC_FAILED);
		ErrorExit((LPTSTR)L"HeapReAlloc");
	}

	if (!ReadFile(input_file_, data_input_, left_over_bytes_input_, NULL, NULL)) {
		ErrorExit((LPTSTR)L"ReadFile");
	}


	error_ = BCryptDecrypt(key_handle_, (PUCHAR)data_input_, left_over_bytes_input_, NULL, (PUCHAR)iv_, IV_LEN, (PUCHAR)data_output_, left_over_bytes_input_, &dummy, 0);
	if (error_ != 0x00000000) {
		SetLastError(error_);
		ErrorExit((LPTSTR)L"BCryptEncrypt");
	}

	left_over_bytes_output_ = AnsiX293ForceReversePad(GetProcessHeap(), data_output_, left_over_bytes_input_);


	if (!WriteFile(output_file_, data_output_, left_over_bytes_output_, NULL, NULL)) {
		ErrorExit((LPTSTR)L"WriteFile");
	}

	SecureZeroMemory(data_input_, left_over_bytes_input_);
	SecureZeroMemory(data_output_, left_over_bytes_output_);

	HeapFree(GetProcessHeap(), 0, data_input_);
	HeapFree(GetProcessHeap(), 0, data_output_);

	wprintf(L"END Decryption\n\n");
}

void AesFile::PrintData() {

	if (blocks_) {
		wprintf(L"\nBlocks: %llu\n", blocks_);
		wprintf(L"Input File Left Over Bytes: %d Bytes\n", left_over_bytes_input_);
		wprintf(L"Input File Dimension: %lld Bytes\n\n", offset_.QuadPart);

		wprintf(L"Output File Left Over Bytes: %d Bytes\n", left_over_bytes_output_);
		wprintf(L"Output File Dimension: %lld Bytes\n\n", blocks_*BLOCK_DIM + left_over_bytes_output_);
	}
	else {
		wprintf(L"Input File Dimension: %lld Bytes\n", offset_.QuadPart);
		wprintf(L"Output File Dimension: %lld Bytes\n", left_over_bytes_output_);
	}

}