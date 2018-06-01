//*********************************************************************************************
//*                                          CBBS                                             *
//*********************************************************************************************
//* Author:		Ravey Alexandre                                                               *
//* Contact:	CBBS@mars105.net                                                              *
//* Date:		07.2007                                                                       *
//* Summary:	A C++ class implementation of the BBS (Blum Blum Shub) algorithm.             *
//*             This is a pseudorandom number generator intended for cryptographic usage.     *
//*                                                                                           *
//* Copyright:	You may use this code as you wish, as long as you do not sell, use it for     *
//*             commercial application, and you let this copyright notice.                    *
//*             Do not take credit for my work, mark your change in the code and all will be  *
//*             fine. If you improve this code in some way, find bugs, or any thing, please   *
//*             let me know.                                                                  *
//*             You may NOT use this code in a commercial application, you do not write it so *
//*             you do not have to be paid for it. If you want make commercial use of this,   *
//*             contact me.                                                                   *
//*                                                                                           *
//* Disclamer:	This software is provided "as is", without warranty of any kind.              *
//*                                                                                           *
//* Version:	1.0                                                                           *
//* History:	1.0:                                                                          *
//*                 Initial release.                                                          *
//*********************************************************************************************

#include "stdafx.h"

#include "CBBS.hpp"


CBBS::CBBS()								//Constructor
{
	srand((unsigned int)time(NULL));		//Seed one time, else we get the same "random" data in two request same time

	mpz_init(mpz_M);						//Initialize the mpz
	mpz_init(mpz_X);
	mpz_init(mpz_X0);
	mpz_init(mpz_p);
	mpz_init(mpz_q);
	mpz_init(mpz_p1q1);

	error = 0;
	MaxBit = 0;
	BitIndex = 0;

	Running = false;						//Meens that the generator is not initialised
}

CBBS::~CBBS()								//Destructor
{
	if(Running)								//Clear before exit
		Clear();

	mpz_clear(mpz_M);						//Clear values
	mpz_clear(mpz_X);
	mpz_clear(mpz_X0);
	mpz_clear(mpz_p);
	mpz_clear(mpz_q);
	mpz_clear(mpz_p1q1);
}

int CBBS::Init(char* Seedp, char* Seedq, char* Seedx, unsigned int SeedLen)
{
	if(Running)								//Clear before reinit
		Clear();

	CHECK(SeedLen==0,CBBS_ERROR_SEEDLEN)

	if(GetPrime(mpz_p, SeedLen, Seedp)!=0)	//Generate p
		return error;
	if(GetPrime(mpz_q, SeedLen, Seedq)!=0)	//Generate q
		return error;

	mpz_mul(mpz_M, mpz_p, mpz_q);			//M = pq

	mpz_sub_ui(mpz_p, mpz_p, 1);			//(p-1)
	mpz_sub_ui(mpz_q, mpz_q, 1);			//(q-1)
	mpz_mul(mpz_p1q1, mpz_p, mpz_q);		//(p-1)(q-1)

	SetMaxBit();							//Calculate max bit to take from X and store to MaxBit

	InitX(Seedx, SeedLen);					//Generate X0

	Running = true;							//Set running value to true (generator initialised)

	return 0;
}

int	CBBS::Clear()							//Reset the generator
{
	mpz_set_ui(mpz_M, 0);					//Set all vars to 0
	mpz_set_ui(mpz_X, 0);
	mpz_set_ui(mpz_X0, 0);
	mpz_set_ui(mpz_p, 0);
	mpz_set_ui(mpz_q, 0);
	mpz_set_ui(mpz_p1q1, 0);

	error = 0;
	MaxBit = 0;
	BitIndex = 0;

	return 0;
}

unsigned long CBBS::GetpLen(int b)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(b<2||b>36, CBBS_ERROR_BASE)

	return (unsigned long)mpz_sizeinbase(mpz_p, b);
}

unsigned long CBBS::GetqLen(int b)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(b<2||b>36, CBBS_ERROR_BASE)

	return (unsigned long)mpz_sizeinbase(mpz_q, b);
}

unsigned long CBBS::GetMLen(int b)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(b<2||b>36, CBBS_ERROR_BASE)

	return (unsigned long)mpz_sizeinbase(mpz_M, b);
}

unsigned long CBBS::GetXLen(int b)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(b<2||b>36, CBBS_ERROR_BASE)

	return (unsigned long)mpz_sizeinbase(mpz_X, b);
}

unsigned long CBBS::GetMaxBit()
{
	CHECK(!Running, CBBS_ERROR_NOINIT)

	return MaxBit;
}

unsigned long CBBS::GetMaxPeriod()
{
	CHECK(!Running, CBBS_ERROR_NOINIT)

	unsigned long i;

	mpz_t mpz_Y;							//Temporary X
	mpz_init(mpz_Y);

	mpz_set(mpz_Y, mpz_X);					//Store X to Y
	i = 0;

	while(mpz_cmp(mpz_Y, mpz_X0)!=0)
	{
		mpz_powm_ui(mpz_Y, mpz_Y, 2, mpz_M);//X = (X²) mod M
		i ++;
	}

	mpz_clear(mpz_Y);

	return i;
}

bool CBBS::GetRndBit()
{
	CHECK(!Running, CBBS_ERROR_NOINIT)

	bool bit;

	if(BitIndex==MaxBit)					//No more bits from this X
		NextX();							//Generate next X
	bit = mpz_tstbit(mpz_X, BitIndex++);	//Get the parity

	return bit;
}

unsigned char CBBS::GetRndByte()
{
	CHECK(!Running, CBBS_ERROR_NOINIT)

	unsigned char	byte;					//Char to return the random value
	int				i;						//Position of the bit to write on the char

	byte = 0;								//Set the byte to 0 (we use OR logical operator to write, so we need it clean)
	i = 7;									//char index, writing from strong bite to lower

	while(i>-1)								//Until byte is filled
	{
		byte |= mpz_tstbit(mpz_X, BitIndex++) << i--;//Get the bite, increment/decrement the counters
		if(BitIndex==MaxBit)				//We take enough bit from X, go to the next one
			NextX();
	}

	return byte;
}

unsigned int CBBS::GetRndInt()
{
	CHECK(!Running, CBBS_ERROR_NOINIT)

	unsigned int	rndint;					//int to return the random value
	int				i;						//Position of the bit to write on the int

	rndint = 0;								//Set the int to 0 (we use OR logical operator to write, so we need it clean)
	i = sizeof(unsigned int)*8;				//int index, writing from strong bite to lower (int size depend of sys)

	while(i>-1)								//Until byte is filled
	{
		rndint |= mpz_tstbit(mpz_X, BitIndex++) << i--;//Get the bite, increment/decrement the counters
		if(BitIndex==MaxBit)				//We take enough bit from X, go to the next one
			NextX();
	}

	return rndint;
}

int CBBS::GetRndBin(unsigned char *rnd, unsigned long Len)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(rnd==NULL, CBBS_ERROR_PTR)
	CHECK(Len==0, CBBS_ERROR_LEN)

	unsigned char	byte;					//temp byte
	int				i;						//Position of the bit to write on the int

	memset(rnd, 0, Len);					//Set rnd to 0 data
	//rndptr = rnd;		//Firt char


	for (int ip=0;ip<Len;ip++) {

        i = 8;								//byte index, writing from strong bite to lower
		byte = 0;							//Set the byte to 0 (we use OR logical operator to write, so we need it clean)



		while(i>-1)							//Until byte is filled
		{
			byte |= mpz_tstbit(mpz_X, BitIndex++) << i--;//Get the bite, increment/decrement the counters
			if(BitIndex==MaxBit)			//We take enough bit from X, go to the next one
				NextX();
		}
		//memcpy(rndptr++, &byte, 1);			//Copy the byte to data
		memcpy(rnd++, &byte, 1);
	}

	return 0;
}

int CBBS::GetRndBinHex(uint8_t *rnd, unsigned long Len)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(rnd==NULL, CBBS_ERROR_PTR)
	CHECK(Len==0, CBBS_ERROR_LEN)

	//unsigned int	rndLen;
	//uint8_t	*rndtmp, *rndtmppos;
	//uint8_t			*rndpos;

	//rndLen = (Len-1)/2;						//Set the random binary length. typcast to int automaticly floor the value.
	//rndtmp = new uint8_t[rndLen];		//Temporary space for the random data

	GetRndBin(rnd, Len);				//Get some random data from generator

	//memcpy(rnd,rndtmp,rndLen);

	//rndpos = rnd;							//rndpos, position in the write buffer
	//rndtmppos = rndtmp;						//rndtmppos, position in the random data

	/*while(rndtmppos<(rndtmp+rndLen))		//Copy data to pstr in hex, eye-readable format
		rndpos += sprintf(rndpos, "%02x", *rndtmppos++);
*/
	//delete [] rndtmp;

	return 0;
}

bool CBBS::GetRndBitAt(unsigned long i, int offset)
{
	CHECK(!Running, CBBS_ERROR_NOINIT)
	CHECK(i==0, CBBS_ERROR_I)
	CHECK(offset>MaxBit, CBBS_ERROR_OFFSET)

	bool	bit;							//Contain the return bit      i
	mpz_t	mpz_exp;						//to calculate the exp of X (2  mod (p-1)(q-1))
	mpz_t	mpz_tmp;						//Temp value (to store the 2 and after, the Xi)

	mpz_init(mpz_exp);
	mpz_init(mpz_tmp);

	mpz_set_ui(mpz_tmp, 2);

	//Formula for calculating X at i
	//        i
	//       2  mod (p-1)(q-1)
	//X  = (X                  ) mod M
	// i     0

	mpz_powm_ui(mpz_exp, mpz_tmp, i, mpz_p1q1);	//2i mod (p-1)(q-1)
	mpz_powm(mpz_tmp, mpz_X0, mpz_exp, mpz_M);	//X0exp mod M
#ifdef CBBS_PRINT_X_INFOS
	printf("\nTmp X: %s\n", mpz_get_str(NULL, 16, mpz_tmp));
#endif //CBBS_PRINT_X_INFOS
	bit = mpz_tstbit(mpz_tmp, offset);		//Get the parity

	mpz_clear(mpz_exp);
	mpz_clear(mpz_tmp);

	return bit;
}

int CBBS::GetSysRnd(char* Dest, unsigned int Len)
{
	unsigned int i;

	for(i=0;i<Len;i++)
		Dest[i] = (char)rand();				//So bad... so, you wanted it... take some *bad* random data from OS.

	return 0;
}

int	CBBS::InitX(char *Seed, unsigned int SeedLen)
{
	char	*rnd,  *rndpos;					//Random data
	mpz_t	mpz_g;

	CHECK(SeedLen==0, CBBS_ERROR_SEEDLEN)

	//No Seed provided, generating one.
	if(Seed == NULL)
	{
		rndpos  = rnd  = new char[SeedLen];

		GetSysRnd(rnd, SeedLen);			//Get some random data from OS
		CharToMpz(mpz_X, rnd, SeedLen);		//Convert random number to mpz
		delete [] rnd;						//Free the buffers
	}
	else //A Seed has been provided, using it
	{
		CharToMpz(mpz_X, Seed, SeedLen);	//Convert seed to mpz
	}

	mpz_init(mpz_g);

	do										//gcd(X,M) must be 1
	{
		mpz_add_ui(mpz_X, mpz_X, 1);		//Add 1 to X
		mpz_gcd(mpz_g, mpz_X, mpz_M);		//Find the Greatest common divisor from X and M
	}
	while(mpz_cmp_ui(mpz_g, 1)!=0);			//If the gcd is not 1, get next X and recheck

	mpz_clear(mpz_g);

	NextX();								//Make X0 (the previous was X-1)
	mpz_set(mpz_X0, mpz_X);					//Store X0 for further check
	NextX();								//Make X1, we don't use X0
	BitIndex = 0;							//Index of the bit to take from X, 0 = first light weight bit

#ifdef CBBS_PRINT_X_INFOS
	printf("\nX0: %s\n", mpz_get_str(NULL, 16, mpz_X0));
	printf("\nX1: %s\n", mpz_get_str(NULL, 16, mpz_X));
#endif //CBBS_PRINT_X_INFOS
	return 0;
}

int CBBS::NextX()
{
	mpz_powm_ui(mpz_X, mpz_X, 2, mpz_M);	//X = (X²) mod M
#ifdef CBBS_PRINT_X_INFOS
	printf("\nNew X: %s\n", mpz_get_str(NULL, 16, mpz_X));
#endif //CBBS_PRINT_X_INFOS

	BitIndex = 0;							//Continue to take bit from first

#ifdef CBBS_PERIOD_CHECK
	if(mpz_cmp(mpz_X0, mpz_X)==0)			//Check if X = X0
		error = CBBS_ERROR_LOOP;			//The generator is in loop, max period here
#endif //CBBS_PERIOD_CHECK					//But we continue, just notice the error

	return 0;
}

int CBBS::SetMaxBit()
{
	mpfr_t			mpfr_l, mpfr_M;			//temp mpfr var
	mpfr_rnd_t		mpfr_rnd;

	mpfr_init(mpfr_l);						//Init temp var
	mpfr_init(mpfr_M);

	mpfr_rnd = mpfr_get_default_rounding_mode();//Get round mode to rnd (just for code lisibility)

	mpfr_set_z(mpfr_M, mpz_M, mpfr_rnd);	//put M in mpfrM for use with MPFR
	mpfr_log2(mpfr_l, mpfr_M, mpfr_rnd);	//Calc log2(M)
	mpfr_log2(mpfr_l, mpfr_l, mpfr_rnd);	//Calc log2(log2(M))
	mpfr_floor(mpfr_l, mpfr_l);				//Round to lower int (if we can take 2.9 bit we take only 2. obvious)
	MaxBit = mpfr_get_ui(mpfr_l, mpfr_rnd);	//Store the number in MaxBit

	mpfr_clear(mpfr_M);						//temp can ben deleted
	mpfr_clear(mpfr_l);

	return 0;
}

int CBBS::GetPrime(mpz_t mpz_p, unsigned int SeedLen, char* Seed)
{
	char	*rnd,  *rndpos;					//Random data

	CHECK(SeedLen==0, CBBS_ERROR_SEEDLEN)

	//No Seed provided, generating one.
	if(Seed == NULL)
	{
		rndpos  = rnd  = new char[SeedLen];

		GetSysRnd(rnd, SeedLen);			//Get some random data from OS
		rnd[SeedLen] |= 0x01;				//Set the first bit of p, ensure that p is odd
		rnd[0] |= 0x80;						//Set the last bit of p, ensure that the number is max length
		CharToMpz(mpz_p, rnd, SeedLen);		//Convert random number to mpz
		delete [] rnd;						//Free the buffers
	}
	else //A Seed has been provided, using it
	{
		Seed[SeedLen] |= 0x01;				//Set the first bit of p, ensure that p is odd
		Seed[0] |= 0x80;					//Set the last bit of p, ensure that the number is max length
		CharToMpz(mpz_p, Seed, SeedLen);	//Convert seed to mpz
	}

	//While p is not a prime number and p is not congruent to 3 (mod 4)
	while((!mpz_probab_prime_p(mpz_p, CBBS_PROB_PRIME))||(mpz_fdiv_ui(mpz_p, 4)!=3))
		mpz_nextprime(mpz_p, mpz_p);		//Get the next prime number to p

	//At this point we must have a p wich is prime and congruent to 3 (mod 4)
	return 0;
}

int CBBS::CharToMpz(mpz_t mpz_mpz, char *chr, unsigned int Len)
{
	char	*pstr,  *pstrpos;				//Temp buffer
	char	*chrpos;

	pstrpos = pstr = new char[(Len*2)+1];	//Size of data *2 (for hex) and +1 for zero trailing
	chrpos = chr;							//Getting start pos

	while(chrpos<(chr+Len))					//Copy data to pstr in hex, eye-readable format
		pstrpos += sprintf(pstrpos, "%02x", (unsigned char)*chrpos++);

	mpz_init_set_str(mpz_mpz, pstr, 16);	//Put the number in mpz using pstr base 16

	delete [] pstr;							//Free the buffer

	return 0;
}
