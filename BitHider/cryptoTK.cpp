#include "stdafx.h"

#include "CBBS.hpp"
#include "cryptoTK.hpp"

void HexStringToHexValue(char *input_str , uint8_t *hex_values , int input_string_len) {

    input_string_len = input_string_len /2;

    char tmp[2];

    for (int i=0;i<input_string_len;i++) {

    tmp[0] = input_str[ i+i ];
    tmp[1] = input_str[ i+i+1 ];

    sscanf(tmp, "%hhx",&hex_values[i]);
    }
}

void PrintHex(uint8_t * str,int len) {

        for(int i=0;i<len;i++) {
        printf("%.2x", str[i]);
        }
        printf("\n");
}

void SetColor(int ForgC) {

 WORD wColor;

 HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
 CONSOLE_SCREEN_BUFFER_INFO csbi;

 if(GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
      wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
      SetConsoleTextAttribute(hStdOut, wColor);
 }
}

UINT64 RandomInterval(UINT64 ran, UINT64 itv_max, UINT64 itv_min) {

    UINT64 rad =  ran % (itv_max + 1 - itv_min) + itv_min ;
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