#include "stdafx.h"

#include "CBBS.hpp"
#include "cryptoTK.hpp"

void HexStringToHexValue(char *input_str , uint8_t *output_hex_values , int input_string_len) {

    input_string_len = input_string_len /2;

    char tmp[2];

    for (int i=0;i<input_string_len;i++) {

    tmp[0] = input_str[ i+i ];
    tmp[1] = input_str[ i+i+1 ];

    sscanf(tmp, "%hhx",&output_hex_values[i]);
    }
}


void PrintHex(uint8_t * hex,int buffer_bytes) {

        for(int i=0;i<buffer_bytes;i++) {
        printf("%.2x", hex[i]);
        }
        printf("\n");
}


INT8 CheckHexString(LPVOID str_add, INT str_len) {

	for (int i = 0; i < str_len; i++) {
		if ((*((PUCHAR)str_add + i) < 48) || (*((PUCHAR)str_add + i) > 57) && (*((PUCHAR)str_add + i) < 97) || (*((PUCHAR)str_add + i) > 102)) {
			return -1;
		}

	}
	return 0;
}


UINT64 RandomInterval(UINT64 rand_num, UINT64 itv_max, UINT64 itv_min) {

    UINT64 rad =  rand_num % (itv_max + 1 - itv_min) + itv_min ;
    return rad;
}


INT8 SecureFileDelete(int block_len, int seed_len, char *str) {



    FILE *file;
    unsigned long long fsize;

    BYTE *pbData1;
    BYTE *pbData2;
    BYTE *pbData3;
    pbData1 = new BYTE [seed_len];
    pbData2 = new BYTE [seed_len];
    pbData3 = new BYTE [seed_len];

    char *Seedp;
    char *Seedq;
    char *Seedx;
    Seedp = (char*)&pbData1;
    Seedq = (char*)&pbData2;
    Seedx = (char*)&pbData3;

    for (int i=0;i<4;i++) {

    pCBBS	BBS;								//BBS is a pointer to the instance of the class CBBS
    BBS = new CBBS;

//    WinBCryptoSeed(seed_len , pbData1 );

//	WinBCryptoSeed(seed_len , pbData2 );

//	WinBCryptoSeed(seed_len , pbData3 );


    BBS->Init(Seedp, Seedq, Seedx, seed_len);


    file = fopen( str ,"w+");

    if (file == NULL) {
    perror("File 1 error");
	return(-1);
    }

    _fseeki64(file,0,SEEK_END);
    fsize= _ftelli64(file);
    rewind(file);

    long long int blocks = fsize / block_len;
    int remaining_bytes = fsize % block_len;

    printf("\nSequence %d/4\n",i+1);
    printf("Total blocks for current sequence: %lld\n\n",blocks);

    uint8_t	*buffer;

    for (long long int i=0;i<blocks;i++) {

        printf("Overwriting on block #%llu\n",i);

        buffer = new uint8_t[block_len];

        PrintHex(buffer,block_len);
        system("PAUSE");

        BBS->GetRndBin(buffer,block_len);

        fwrite (buffer , 1, block_len, file);

        delete [] buffer;

        }

        //allocating memory
        buffer = new uint8_t[remaining_bytes];

        //encrypting
        BBS->GetRndBin(buffer,remaining_bytes);

        PrintHex(buffer,block_len);

        fwrite (buffer , 1, remaining_bytes, file);
        fclose (file);

        delete [] buffer;
        delete BBS;
}



        delete [] pbData1;
        delete [] pbData2;
        delete [] pbData3;



        int ret = remove(str);  //delete file

        if(!ret) {
        printf("File deleted successfully");
		return(0);
        }

        printf("Error: unable to delete the file");
		return(-1);
}


void ErrorExit(LPTSTR lpszFunction) {
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Display the error message and exit the process

	if (lpMsgBuf == NULL) {
		lpMsgBuf = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 32);
		StringCchCopy((LPTSTR)lpMsgBuf, 32, L"See Documentation for more info");
	}

	lpDisplayBuf = (LPVOID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));

	StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error 0x%02XL: %s"), lpszFunction, dw, lpMsgBuf);

	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, NULL, MB_OK | MB_ICONWARNING );

	HeapFree(GetProcessHeap(), 0, lpDisplayBuf);
	HeapFree(GetProcessHeap(), 0, lpMsgBuf);
	PostQuitMessage(WM_QUIT);
}


INT AnsiX293ForcePad(HANDLE heap, LPVOID ptr, INT buf_len, UINT8 multiplier) {
	INT final_data_len = buf_len;
	INT8 delta_pad_bytes = 0;

	do {
		delta_pad_bytes++;
		final_data_len++;
	} while (final_data_len % multiplier != 0);

	ptr = HeapReAlloc(heap, HEAP_ZERO_MEMORY, ptr, final_data_len);

	*((PUCHAR)ptr + (final_data_len - 1)) = delta_pad_bytes;

	return final_data_len;
}


INT AnsiX293ForceReversePad(HANDLE heap, LPVOID ptr, INT buf_len) {
	INT8 data_to_remove;
	INT final_len;

	data_to_remove = *((PUCHAR)ptr + (buf_len - 1));

	final_len = buf_len - data_to_remove;

	RtlSecureZeroMemory((LPVOID)((PUCHAR)ptr + final_len), data_to_remove);

	ptr = HeapReAlloc(heap, NULL, ptr, final_len);

	return final_len;
}


CHAR PressAnyKey(HANDLE hstdin, HANDLE hstout, const WCHAR* prompt = NULL) {
	CHAR  ch;
	DWORD  mode;
	DWORD  count;
	COORD exitPrompcoord;
	CONSOLE_SCREEN_BUFFER_INFO stoutinfo;

	GetConsoleScreenBufferInfo(hstout, &stoutinfo);
	exitPrompcoord = stoutinfo.dwCursorPosition;

	// Prompt the user
	if (prompt == NULL) prompt = L"Press any key to continue...\n";
	WriteConsoleW(hstout, prompt, lstrlenW(prompt), &count, NULL);

	// Switch to raw mode
	GetConsoleMode(hstdin, &mode);
	SetConsoleMode(hstdin, 0);

	// Wait for the user's response
	WaitForSingleObject(hstdin, INFINITE);

	// Read the (single) key pressed
	ReadConsoleA(hstdin, &ch, 1, &count, NULL);

	FillConsoleOutputCharacterW(hstout, (TCHAR)' ', lstrlenW(prompt), exitPrompcoord, &count);
	SetConsoleCursorPosition(hstout, exitPrompcoord);

	// Restore the console to its previous state
	SetConsoleMode(hstdin, mode);

	// Return the key code
	return ch;
}


int ScrollByRelativeCoord(HANDLE hStdout, int iRows) {
	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
	SMALL_RECT srctWindow;

	// Get the current screen buffer window position. 

	if (!GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
	{
		printf("GetConsoleScreenBufferInfo (%d)\n", GetLastError());
		return 0;
	}

	// Check whether the window is too close to the screen buffer top

	if (csbiInfo.srWindow.Top >= iRows)
	{
		srctWindow.Top = -(SHORT)iRows;     // move top up
		srctWindow.Bottom = -(SHORT)iRows;  // move bottom up 
		srctWindow.Left = 0;         // no change 
		srctWindow.Right = 0;        // no change 

		if (!SetConsoleWindowInfo(
			hStdout,          // screen buffer handle 
			FALSE,            // relative coordinates
			&srctWindow))     // specifies new location 
		{
			printf("SetConsoleWindowInfo (%d)\n", GetLastError());
			return 0;
		}
		return iRows;
	}
	else
	{
		printf("\nCannot scroll; the window is too close to the top.\n");
		return 0;
	}
}


void SetColor(HANDLE hStdOut, int ForgC) {

	WORD wColor;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	if (GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
		wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
		SetConsoleTextAttribute(hStdOut, wColor);
	}
}


void ClearOutputBuffer(HANDLE hConsole) {
	COORD coordScreen = { 0, 0 };    // home for the cursor 
	DWORD cCharsWritten;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD dwConSize;

	// Get the number of character cells in the current buffer. 

	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		return;
	}

	dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

	// Fill the entire screen with blanks.

	if (!FillConsoleOutputCharacter(hConsole,        // Handle to console screen buffer 
		(TCHAR) ' ',     // Character to write to the buffer
		dwConSize,       // Number of cells to write 
		coordScreen,     // Coordinates of first cell 
		&cCharsWritten))// Receive number of characters written
	{
		return;
	}

	// Get the current text attribute.

	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		return;
	}

	// Set the buffer's attributes accordingly.

	if (!FillConsoleOutputAttribute(hConsole,         // Handle to console screen buffer 
		csbi.wAttributes, // Character attributes to use
		dwConSize,        // Number of cells to set attribute 
		coordScreen,      // Coordinates of first cell 
		&cCharsWritten)) // Receive number of characters written
	{
		return;
	}

	// Put the cursor at its home coordinates.

	SetConsoleCursorPosition(hConsole, coordScreen);
}

void NewLine(HANDLE hStdout) {

	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;

	if (!GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
	{
		MessageBox(NULL, TEXT("GetConsoleScreenBufferInfo"),
			TEXT("Console Error"), MB_OK);
		return;
	}

	csbiInfo.dwCursorPosition.X = 0;

	// If it is the last line in the screen buffer, scroll 
	// the buffer up. 

	if ((csbiInfo.dwSize.Y - 1) == csbiInfo.dwCursorPosition.Y)
	{
		ScrollScreenBuffer(hStdout, 1, csbiInfo);
	}

	// Otherwise, advance the cursor to the next line. 

	else csbiInfo.dwCursorPosition.Y += 1;

	if (!SetConsoleCursorPosition(hStdout,
		csbiInfo.dwCursorPosition))
	{
		MessageBox(NULL, TEXT("SetConsoleCursorPosition"),
			TEXT("Console Error"), MB_OK);
		return;
	}
}

void ScrollScreenBuffer(HANDLE h, INT x, CONSOLE_SCREEN_BUFFER_INFO csbiInfo) {
	SMALL_RECT srctScrollRect, srctClipRect;
	CHAR_INFO chiFill;
	COORD coordDest;

	srctScrollRect.Left = 0;
	srctScrollRect.Top = 1;
	srctScrollRect.Right = csbiInfo.dwSize.X - (SHORT)x;
	srctScrollRect.Bottom = csbiInfo.dwSize.Y - (SHORT)x;

	// The destination for the scroll rectangle is one row up. 

	coordDest.X = 0;
	coordDest.Y = 0;

	// The clipping rectangle is the same as the scrolling rectangle. 
	// The destination row is left unchanged. 

	srctClipRect = srctScrollRect;

	// Set the fill character and attributes. 

	chiFill.Attributes = FOREGROUND_RED | FOREGROUND_INTENSITY;
	chiFill.Char.AsciiChar = (char)' ';

	// Scroll up one line. 

	ScrollConsoleScreenBuffer(
		h,               // screen buffer handle 
		&srctScrollRect, // scrolling rectangle 
		&srctClipRect,   // clipping rectangle 
		coordDest,       // top left destination cell 
		&chiFill);       // fill character and color 
}