#include "stdafx.h"

#include "CBBS.hpp"
#include "cryptoTK.hpp"


int8_t win_bcrypto_seed (int len, BYTE *pbData) {
BCryptGenRandom(NULL, pbData, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
return 0;
}

int8_t win_crypto_seed(int len, BYTE *pbData) {

HCRYPTPROV   hCryptProv;


//-------------------------------------------------------------------
// Begin processing.

//-------------------------------------------------------------------
// Acquire a cryptographic provider context handle.
printf("CryptAcquireContext");

if( CryptAcquireContext( &hCryptProv, NULL, NULL, PROV_RSA_FULL, 0) ) {
    printf(" [ OK ]\n");
}
else {
    printf(" [ FAIL ]\n");
    if (WARNING) {
        Init_Error();
    }
    return -1;
}


// Generate a random initialization vector.

printf("Random sequence");

if(CryptGenRandom( hCryptProv, len, pbData) ) {
     printf(" [ OK ]\n");
}

else {
    printf(" [ FAIL ]\n");
    if (WARNING) {
        Init_Error();
    }

    return -1;
}

return 0;
}

void hex_value_string_to_hex_value(char *input_str , uint8_t *hex_values , int input_string_len) {

    input_string_len = input_string_len /2;

    char tmp[2];

    for (int i=0;i<input_string_len;i++) {

    tmp[0] = input_str[ i+i ];
    tmp[1] = input_str[ i+i+1 ];

    sscanf(tmp, "%hhx",&hex_values[i]);
    }
}

void print_hex(uint8_t * str,int len) {

        for(int i=0;i<len;i++) {
        printf("%.2x", str[i]);
        }
        printf("\n");
}

char* get_filename(char str[], int len) {

static char file_name[256]={0};

int slash_pos;
int point_pos = NULL;
char enc_text[20] ={"_encrypted"};

int enc_text_len=strlen(enc_text);

for (int i=len; i>0; i--) {
    if (str[i] == '\\') {
        slash_pos = i;
        break;
    }
    if ( (str[i] == '.') && (point_pos == NULL)) {
        point_pos = i;
    }
}


for (int i=slash_pos+1,y=0; str[i]!='\0';i++) {
        file_name[y] = str[i];

        if (point_pos-1 == i) {
            for (int x=0;x<enc_text_len;x++) {
                y++;
                file_name[y] = enc_text[x];
            }
        }
        y++;
}


return file_name;

}

void SetColor(int ForgC) {


 WORD wColor;

  HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO csbi;

                       //We use csbi for the wAttributes word.
 if(GetConsoleScreenBufferInfo(hStdOut, &csbi))
 {
                 //Mask out all but the background attribute, and add in the forgournd color
      wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
      SetConsoleTextAttribute(hStdOut, wColor);
 }
}

unsigned long long int random_interval(unsigned long long int ran, int itv_max, int itv_min) {


    //(max_number + 1 - minimum_number) + minimum_number

    long long int rad =  ran % (itv_max + 1 - itv_min) + itv_min ;
    return rad;
}

int8_t secure_file_delete(int block_len, int seed_len, char *str) {



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

    win_crypto_seed(seed_len , pbData1 );

    win_crypto_seed(seed_len , pbData2 );

    win_crypto_seed(seed_len , pbData3 );


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

        print_hex(buffer,block_len);
        system("PAUSE");

        BBS->GetRndBin(buffer,block_len);

        fwrite (buffer , 1, block_len, file);

        delete [] buffer;

        }

        //allocating memory
        buffer = new uint8_t[remaining_bytes];

        //encrypting
        BBS->GetRndBin(buffer,remaining_bytes);

        print_hex(buffer,block_len);

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

int Init_Error() {


     int msgboxID = MessageBox(
        0,
        TEXT("Random number generator didn't inizialize, run program with Administrator Permission. Do you want to continue anyway (NOT RECOMMENDED)?"),
        TEXT("Error"),
        MB_TASKMODAL | MB_TOPMOST | MB_YESNO | MB_DEFBUTTON2 | MB_ICONSTOP
    );

    switch (msgboxID)
    {
    case IDNO:
        exit(0);
        break;
    }


    return msgboxID;
}

void DisplayError(LPCWSTR lpszFunction) {
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
		0,
		NULL);

	lpDisplayBuf =
		(LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf)
			+ lstrlen((LPCTSTR)lpszFunction)
			+ 40) // account for format string
			* sizeof(TCHAR));

	if (FAILED(StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error code %d as follows:\n%s"),
		lpszFunction,
		dw,
		lpMsgBuf)))
	{
		printf("FATAL ERROR: Unable to output error code.\n");
	}

	_tprintf(TEXT("ERROR: %s\n"), (LPCTSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);

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

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}