/*******************************************************************************
********************************************************************************
This program is part of the RC-Crypt suite
that implements rc5 128 bit block cipher.

Copyright (C) 2001-5 R.G.Jones

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

Email:rich@ricksoft.co.uk
********************************************************************************
********************************************************************************/

#ifndef __RCCRYPT_H
#define __RCCRYPT_H

/*Define the magic numbers used for RC5-128*/
#define P64 0xb7e151628aed2a6bLL /* P64=(e-2)*2^64 */
#define Q64 0x9e3779b97f4a7c15LL /* Q64=(L-2)*2^64 where L is Golden Ratio*/

/*Other Definitions*/
#define ULLONG unsigned long long
#define ULONG unsigned long
#define UBYTE unsigned char
#define BLOCK_SIZE 16
#define MAX_BYTES_IN_KEY 64
#define MAX_FILE 1024
typedef enum boolean {FALSE,TRUE} BOOLEAN;

/************************************************************/
/*Definitions to enforce standard byte ordering*/
#ifdef hpux
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#ifdef  _BIG_ENDIAN 
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) ((((x) & 0x00000000000000ffLL) << 56) | \
				(((x) & 0x000000000000ff00LL) << 40) | \
				(((x) & 0x0000000000ff0000LL) << 24) | \
				(((x) & 0x00000000ff000000LL) <<  8) | \
				(((x) & 0x000000ff00000000LL) >>  8) | \
				(((x) & 0x0000ff0000000000LL) >> 24) | \
				(((x) & 0x00ff000000000000LL) >> 40) | \
				(((x) & 0xff00000000000000LL) >> 56))
#define ntohll(x) ((((x) & 0x00000000000000ffLL) << 56) | \
				(((x) & 0x000000000000ff00LL) << 40) | \
				(((x) & 0x0000000000ff0000LL) << 24) | \
				(((x) & 0x00000000ff000000LL) <<  8) | \
				(((x) & 0x000000ff00000000LL) >>  8) | \
				(((x) & 0x0000ff0000000000LL) >> 24) | \
				(((x) & 0x00ff000000000000LL) >> 40) | \
				(((x) & 0xff00000000000000LL) >> 56))
#endif /*_BIG_ENDIAN*/
#endif /*hpux*/

/******************************/
/*Debug mode stuff*/
#ifdef DEBUG
extern void uprint (char *name, ULLONG thing);
#else
#define uprint(A,B) ((void)0)
#endif 

/******************************/
/*More functions defined elsewhere*/
extern ULLONG lrotate(ULLONG num,ULLONG n);
extern ULLONG rrotate(ULLONG num,ULLONG n);
extern char get_random_char();
extern void bail (char *c);
extern ULLONG remainder(ULLONG numerator, ULLONG divisor);

#define max(A,B) (((A) > (B)) ? (A) : (B) )

/******************************/
/* Define the structure used to pass data from parent to child process */
typedef struct options {
	char key[MAX_BYTES_IN_KEY + 1];		/* up to 64 hex chars for the ascii key */
	long length;		/* number of chars in the ascii key */
	long rounds;		/* number of rounds to use */
	BOOLEAN crypt;		/* whether to encrypt or decrypt */
	BOOLEAN pseudo;		/* whether to pseudo-random or not */
	char infile[MAX_FILE + 1];	/* input file (=STDIN if that's what's wanted) */
	char outfile[MAX_FILE + 1];	/* output file (=STDOUT if that's what's wanted) */
} RCC_OPTIONS;
#endif

