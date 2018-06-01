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

#pragma once


#include "stdafx.h"

#define CHECK(cond,err)		if(cond){error = err; return err;}//set the error and return the code

#define CBBS_PROB_PRIME		10		//Number of Miller-Rabin tests to run. default 10, adjust as you wich.
#define CBBS_DEF_SEED_LEN	128		//Default seed len int byte, when no seed is provided. Default = 128 byte = 1024 bit

//Errors codes
#define CBBS_ERROR_LOOP		100;	//The generator loop, means X0 = X. You *MUST* reseed the generator.
#define CBBS_ERROR_SEEDLEN	101;	//Invalid seedlen provided
#define	CBBS_ERROR_BASE		102;	//Base (b) provided is not between 2 and 36 inclusive
#define	CBBS_ERROR_PTR		103;	//Wrong pointer provided (NULL)
#define	CBBS_ERROR_LEN		104;	//0 size provided
#define	CBBS_ERROR_I		105;	//I is not valid
#define	CBBS_ERROR_OFFSET	106;	//OFFSET is > MaxBit
#define	CBBS_ERROR_NOINIT	107;	//Generator not initialised


//Configuration
#define CBBS_PERIOD_CHECK			//Check each X with X0. Take a little time, but never to sure ;)
//#define CBBS_PRINT_X_INFOS		//Print X when generated

typedef class CBBS {
public:
	CBBS();						//Constructor
	virtual ~CBBS();			//Destructor

								//Initialization function
	int	Init(char *Seedp = NULL, char *Seedq = NULL, char *Seedx = NULL, unsigned int SeedLen = CBBS_DEF_SEED_LEN);

	//Clear function
	int	Clear();

	//Some eye-candy functions (maybe of some utility...)
	unsigned long	GetpLen(int b);	//Return the length of p in base b
	unsigned long	GetqLen(int b);	//I let you guess this time...
	unsigned long	GetMLen(int b);	//...
	unsigned long	GetXLen(int b);	//...
	unsigned long	GetMaxBit();	//Return MaxBit
	unsigned long	GetMaxPeriod();	//Calculate the max period before loop, don't use with numbers bigger than 2byte.

									//All random function, each one make the next value of X and return the asked length of random data
	bool			GetRndBit();	//A bit, alone, all naked
	unsigned char	GetRndByte();	//A byte, maked by 8 bit
	unsigned int	GetRndInt();	//An int, depending on int length for the sys (generaly 32bit)
									//Random binary data, put to rnd. Len is byte NOT bit (and char, because is the easyest way to get binary data.)
	int				GetRndBin(unsigned char *rnd, unsigned long Len);
	//Random binary data in hex exe-readable format. Len is the of rnd in byte wich is TWICE the len of random binary
	//Len is the number of digits in hex string. Don't forget the trailling 0 (to get 32bit in hex, 9 byte buffer)
	int				GetRndBinHex(uint8_t *rnd, unsigned long Len);
	//Interesting function, get the bit produced by Xi (i start from X0) offset is the bit to take from X0
	bool			GetRndBitAt(unsigned long i, int offset = 0);

	int	error;						//Contain the last error code

private:
	//Get some *not at all* random data from the sys, in case de user provided no seed
	int	GetSysRnd(char *Dest, unsigned int Len);
	//Initialize X0, the first state of the generator
	int	InitX(char *Seed = NULL, unsigned int SeedLen = CBBS_DEF_SEED_LEN);
	//Generate the next value of X
	int	NextX();
	//Set MaxBit to log2(log2(M)) wich is the max number of bit we can take from X
	int	SetMaxBit();
	//found a prime number, congruent to 3 (mod 4). start from Seed
	int	GetPrime(mpz_t p, unsigned int SeedLen = CBBS_DEF_SEED_LEN, char *Seed = NULL);
	//Convert a char (random output from OS) to an mpz number
	int	CharToMpz(mpz_t mpz, char *chr, unsigned int Len);

	mpz_t	mpz_X;					//The actual X state of the generator
	mpz_t	mpz_X0;					//Initial X, used to verfiy we are not looping
	mpz_t	mpz_p;					//first blum prime number -1 (p-1)
	mpz_t	mpz_q;					//second blum prime number -1 (q-1)
	mpz_t	mpz_M;					//M = pq                    i
	mpz_t	mpz_p1q1;				//(p-1)(q-1) needed to get X
	bool	Running;				//True if the generator is initialised
	unsigned int	MaxBit;			//Max number of bit to take from X calculated from log2(log2(M))
	unsigned int	BitIndex;		//Index of the bit to take from X

} CBBS, *pCBBS;