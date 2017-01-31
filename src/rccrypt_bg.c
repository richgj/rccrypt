/*****************************************************************************
******************************************************************************
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
File format:
The encoded output is an integer number of 16 byte blocks.
The first block is pseudo random data.
The second block to the last but one block are encoded data.
If the data does not fill the last but one block, it is padded
with pseudo random data to make it sixteen bytes.
The last block is pseudo random data, apart from the lowest
four bits of the first byte. These are the number of bytes
used to pad the last but one byte (ie 0-15).
********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/shm.h>

#include "rccrypt.h"

/************************************************************/
/*Global variables used by different subroutines*/
static long rounds;	/*number of rounds required (0..255)*/
static ULLONG *S;	/*Pointer to subkey array*/
static BOOLEAN pseudo_random;		/*To decide if each block is xor-ed with previous block*/
static ULONG xor_array[5];	/*Used to create aligned character buffer for xor with data*/
static char *xor_block = (char *)xor_array;
					/*xor_block must be aligned to a long as a type conversion is applied*/
					/* The xor block is the previous ENCRYPTED data block */
static BOOLEAN firstblock;	/*To check if this is the first block*/
static BOOLEAN secondblock;	/*To check if this is the second block*/

/********************************************************************************/
/* The following are definitions of subroutines defined after main*/
void encrypt_it(char *buffer);
void decrypt_it(char *buffer);

/********************************************************************************/
/* Main program begins here*/
/********************************************************************************/
int main(int argc, char **argv)
{
/********************************************************************************/
/*Declare all variables here*/
long i;	/*used for loop control*/
int one_char;	/*used for getting chars from the input stream*/
FILE *input;	/*either from a file or the standard input*/
FILE *output;	/*either to a file or the standard ouput*/
UBYTE *padded_keystring;	/*Pointer to padded array for the key to fit into*/
UBYTE sub_array[9];		/*array to get chunks out of the padded array*/
ULLONG *K;	/*Pointer for integer access to key*/
long c;		/*number of 64 bit integers in the key*/
long t;		/*number of subkeys:2*(rounds+1)*/
long j,k;	/*used to access arrays*/
long num_chars_in_keystring;
long num_chars_in_padded_keystring;
long num_lls_in_key;
char k_chars[MAX_BYTES_IN_KEY + 1];	/*points to key string given in command line*/
char infile_buff[MAX_FILE + 1];	/* copy of the infile name passed via shared mem */
char *infile;	/*points to filename if passed via shared mem*/
char outfile_buff[MAX_FILE + 1]; /* copy of the outfile name passed via shared mem */
char *outfile;	/*points to filename if passed vi shared mem*/
char *tail;	/*for char to number conversion checking*/
ULONG temp;	/*used for VERY temporary storage of a number...*/
ULLONG A,B;	/*64-bit integers used to mangle sub keys*/
ULONG char_array[5];	/*Used to create aligned character buffer that can be printed*/
char *buffer = (char *)char_array;
					/*buffer must be aligned to a long as a type conversion is applied*/
ULONG previous_array[5];	/*Used to create aligned character buffer that can be printed*/
char *previous_block = (char *)previous_array;
					/*previous_block must be aligned to a long as a type conversion is applied*/
size_t count, rd_count;		/*how many items were reading/writing the stream*/
UBYTE pad_value;	/*Number of pad characters used when encoding*/
int to_print;		/*how much of the block to print when decoding*/
void (*crypt_option)(char *);	/*Function pointer to decide whether to decrypt/encrypt*/

int shm_key;	/* shared memory key based on parent process pid */
RCC_OPTIONS *rcc_options;	/* holds the data to be written to the shared memory */

/********************************************************************************/
/*Create a random seed based on the calendar time*/
	srandom(time(NULL));

/********************************************************************************/
/* Get the options from the shared memory area */

/* get the key and attach the memory */

	shm_key = shmget(getpgrp(), sizeof(RCC_OPTIONS), SHM_RDONLY );

	if (shm_key < 0)
	{
		bail("Failed to create shared memory area");
	}

/* attach the memory here */
	rcc_options = shmat(shm_key, NULL, 0);

	if (rcc_options < 0)
	{
		bail("Unable to attach shared memory");
	}

/* Copy the data from shared memory to local variables */
	num_chars_in_keystring = rcc_options->length;
	rounds = rcc_options->rounds;
	pseudo_random = rcc_options->pseudo;

	/* sort out crypt option */
	if(rcc_options->crypt)
	{
		crypt_option = encrypt_it;
	}
	else
	{
		crypt_option = decrypt_it;
	}

	/* copy the key */
	strncpy(k_chars, rcc_options->key, MAX_BYTES_IN_KEY + 1);

	/* copy the infile */
	if (strncmp("STDIN", rcc_options->infile, 5) == 0)
	{
		infile = NULL;
	}
	else
	{
		strncpy (infile_buff, rcc_options->infile, MAX_FILE);
		infile_buff[MAX_FILE] = '\0';
		infile = infile_buff;
	}

	/* copy the outfile */
	if (strncmp("STDOUT", rcc_options->outfile, 6) == 0)
	{
		outfile = NULL;
	}
	else
	{
		strncpy (outfile_buff, rcc_options->outfile, MAX_FILE);
		outfile_buff[MAX_FILE] = '\0';
		outfile = outfile_buff;
	}

/* unattach from the memory */
	shmdt((void *)rcc_options);

/* Tell the parent process we've got the data */
	kill(getpgrp(), SIGUSR1);

/********************************************************************************
Converting the key....
Each 2 chars in the key is one byte.
One long has 8 chars.
One Long long has 16 chars.
Create a string containing the chars in the key, padded with enough zeros
at the beginning to make it up to an integer number of long longs.
Create the final long long array the right size.
The use atoul(base 16) to convert the char array 8 chars at a time into the final array.
********************************************************************************/
	num_lls_in_key=num_chars_in_keystring/BLOCK_SIZE;

	if (get_remainder(num_chars_in_keystring,16)>0)
		num_lls_in_key +=1;

	c = num_lls_in_key;

	num_chars_in_padded_keystring = num_lls_in_key*BLOCK_SIZE;

/*create the padded array*/

	padded_keystring = (UBYTE *)malloc(num_chars_in_padded_keystring+1);
	if (NULL == padded_keystring)
		bail("Malloc error:padded_keystring");

/*fill the array with zeros then copy the key to the end of it*/

	memset(padded_keystring, '0', num_chars_in_padded_keystring);

/*make sure it finishes with a null char so can use string fns on it*/
	padded_keystring[num_chars_in_padded_keystring] = '\0';
	strncpy((char *)padded_keystring +
			num_chars_in_padded_keystring -
			num_chars_in_keystring,
			k_chars,
			num_chars_in_keystring);

/*create the long long array for the key*/#

	K = (ULLONG *) malloc( num_lls_in_key * 8 );
	if ( NULL == K)
		bail("Malloc error:K");

/*fill it with zeros*/

	memset( K, 0, num_lls_in_key * 8);

/*now convert each chunk of 8 chars to a long and copy it into the array*/

	for (i=0,j=0; i<num_chars_in_padded_keystring; i+=8,j+=4)
	{
		strncpy((char *)sub_array,(char *)padded_keystring+i,8);
		sub_array[8]='\0';

		errno = 0;
		temp = strtoul((char *)sub_array, &tail, BLOCK_SIZE);
		if (tail != (char *)(sub_array+8))
			bail("Key must be a hex number");

		/*Put key values in network order*/
		temp = htonl( temp );

		if(errno)
			bail("Key: overflow on conversion");

		/*copy the ULONG into the string*/
		memcpy(((char *)K)+j, (char *)&temp, 4);
	}


/********************************************************************************/
/*Now fill the subkeys with pseudo random bits*/

	t = 2 * (rounds+1);

	S = (ULLONG *)malloc(t*8);
	if (NULL == S)
		bail("Malloc Error:S");

	S[0] = P64;
	for(i=1; i<t; i++)
	{
		S[i] =S [i-1] + Q64;
	}

	/*Convert subkeys to network byte order*/
	for (i=0; i<t; i++)
	{
		S[i] = htonll(S[i]);
		uprint ("Subkey",S[i]);
	}

	for (i=0; i<c; i++)
	{
		uprint("Host order key",ntohll(K[i]));
		uprint("Network order key",K[i]);
	}

	/*Mangle the subkeys with the Key*/
	k = j = 0;
	A = B = 0;
	for(i=0; i < 3*max(t,c) ;i++)
	{
	/*At this point, both K and S are in network byte order*/
		S[j] = htonll(lrotate( ntohll(S[j]) + A + B, 3));
		K[k] = htonll(lrotate( ntohll(K[k]) + A + B, A + B));
		A = ntohll(S[j]);
		B = ntohll(K[k]);
		if (++j >= t) j=0;
		if (++k >= c) k=0;
	}

	/*Put the mangled keys into host order*/
	for (i=0; i<t; i++)
	{
		S[i] = ntohll(S[i]);
	}

	/*Print out mangled keys*/
	for (i=0; i<t; i++)
	{
		uprint("Mangled Subkey=",S[i]);
	}

/********************************************************************************/
/*Determine where our input will be from*/
	if (NULL == infile)
	{
		input=stdin;/*get info from the standard input*/
		/*this allows a user to pipe stuff in...*/
	}
	else
	{
		input=fopen(infile,"r");
		if(NULL == input)
			bail("Failed to open input file");
	}

/********************************************************************************/
/*Determine where the output goes to*/
	if (NULL == outfile)
	{
		output = stdout; /*send output to the standard output*/
		/*allows a user to pipe or redirect stuff out*/
	}
	else
	{
		output = fopen(outfile,"w");
		if (NULL == output)
			bail("Failed to open output file");
	}

/*********************************************************************************/
/* Set the "xor block"to zeros in case the system doesn't do it for us */
for (i=0; i< BLOCK_SIZE; i++)
{
	xor_block[i] = 0;
}
/********************************************************************************
Now we can do some encryption
We need to get 2 64-bit words for each block to encrypt
if there is not enough data, we need to pad the words with extra bytes
this program uses random printable chars for padding
********************************************************************************/

	pad_value = 0;
	firstblock = TRUE;
	secondblock=FALSE;

	one_char=getc(input);

	if ((firstblock) && (crypt_option != decrypt_it))
	{
		/*
		* When encoding;
		* Output some random data for the first block.
		* This will be used to
		* xor each block of data with a previous block if requested
		*/
		/*Fill the buffer with random data*/
		for (i=0; i<BLOCK_SIZE; i++)
			buffer[i] = get_random_char();

		/*Do the same encoding as before*/
		crypt_option(buffer);

		/*now output the data we worked on*/
		count=fwrite(buffer, 1, BLOCK_SIZE, output);
		if (count != BLOCK_SIZE)
			bail("Error in writing to output stream-first block\n");

		firstblock=FALSE;
	}

	while(one_char!=EOF)
	{
		ungetc(one_char,input);/*put back the character as it isn't an eof*/
		/*
		* Read BLOCK_SIZE bytes of data into the buffer
		* If we don't get BLOCK_SIZE bytes, pad the buffer with
		* random printable characters to overwrite previous values.
		* When decoding, we will always have BLOCK_SIZE bytes.
		*/
		rd_count = fread(buffer, 1, BLOCK_SIZE, input);

		if (rd_count < BLOCK_SIZE)
		{
			pad_value = BLOCK_SIZE - rd_count;
			for (i=rd_count; i<BLOCK_SIZE; i++)
				buffer[i] = get_random_char();
		}

		/*Do the encryption/decryption*/
		crypt_option (buffer);

		one_char=getc(input);

		/*Decide whether to print out all the data or not*/
		if (crypt_option == decrypt_it)
		{
			/*
			* How many bytes should we print from
			* the previous block?
			*/
			if (EOF == one_char) /*if true, we are on the last  block*/
			{
				/*
				* Get the pad value
				* buffer should be in network byte order
				*/
				memcpy (&pad_value, buffer, 1);

				/*throw away the top 4 bits*/
				pad_value &= 0xf;
				to_print = BLOCK_SIZE - pad_value;
			}
			else
			{
				to_print = BLOCK_SIZE;
			}

			/*We only start printing output when we get to the third block*/
			if ((!firstblock) && (!secondblock))
			{
				count = fwrite (previous_block, 1, to_print, output);
				if ( count != to_print )
					bail("Error in writing to output stream-not firstblock");
			}
			else
			{
				firstblock = FALSE;
				if (secondblock)
					secondblock = FALSE;
				else
					secondblock = TRUE;
			}

		}
		else /*encoding*/
		{
			/*output the data we encoded*/
			count = fwrite (buffer, 1, BLOCK_SIZE, output);
			if (count != BLOCK_SIZE)
				bail("Error in writing to output stream-encoding");

			if (EOF == one_char) /*if true, we are on the last  block*/
			{
				/*Output the padding number*/
				/*Fill the buffer with random data*/
				for (i=0; i<BLOCK_SIZE; i++)
					buffer[i] = get_random_char();

				/*Put the pad size into the correct bits of the first byte*/
				pad_value &= 0xf;	/*lower 4 bits*/
				*buffer &= 0xf0;	/*upper 4 bits*/
				*buffer |= pad_value;	/*join them up*/

				/*Do the same encoding as before*/
				crypt_option(buffer);

				/*now output the data we worked on*/
				count=fwrite(buffer, 1, BLOCK_SIZE, output);
				if (count != BLOCK_SIZE)
					bail("Error in writing to output stream-last block\n");
			}
		}
		/*
		* Copy the current block into the previous block
		* so it isn't overwritten
		*/
		memcpy (previous_block, buffer, BLOCK_SIZE);
	}

/********************************************************************************/
/*Close file handlers to ensure all data is flushed*/
if (input != stdin) fclose(input);
if (output != stdout) fclose(output);

/********************************************************************************/
/*Free up resources*/
/*Not really needed as this is the end of the program, but it's good practise*/
free(padded_keystring);
free(K);
free(S);

return (0);
}/*end of Main*/

/********************************************************************************/
/*Encrypt the buffer sent to us*/
void encrypt_it(char *buffer)
{
ULLONG *L,*R;		/*pointers to parts of the buffer-left and right ULLONG chunks*/
int i;

	/*now we have sixteen bytes ready to work on*/
	/*split it into two ULLONGs, left and right*/

	L = (ULLONG *)buffer;
	R = (ULLONG *)(buffer+8);

	/*Put the data into host byte order*/
	*L = ntohll (*L);
	*R = ntohll (*R);

	/*run the data through the encryption the right number of times*/
	*L += S[0];
	*R += S[1];
	for (i=1;i<=rounds;i++)
	{
		*L = S[2*i] + lrotate( *L ^ *R, *R);
		*R = S[2*i+1] + lrotate(*R ^ *L, *L);
	}

	/*Convert buffer back to network order*/
	*L = htonll(*L);
	*R = htonll(*R);

	if (pseudo_random)
	{
		for (i=0; i<BLOCK_SIZE; i++)
		{
			buffer[i] ^= xor_block[i];
		}
		/* remember the encrypted block */
		memcpy (xor_block, buffer, BLOCK_SIZE);
	}

	return;
}

/********************************************************************************/
/*Decrypt the buffer sent to us*/
void decrypt_it(char *buffer)
{
ULLONG *L,*R;		/*pointers to parts of the buffer-left and right ULLONG chunks*/
int i;
ULONG temp_array[5];	/*Used to create aligned character buffer that can be printed*/
char *temp_block = (char *)temp_array;

	if (pseudo_random)
	{
		/* The buffer is the encrypted data used to xor */
		memcpy(temp_block, buffer, BLOCK_SIZE);

		for (i=0; i<BLOCK_SIZE; i++)
		{
			buffer[i] ^= xor_block[i];
		}

		/* remember the data for the next xor */
		memcpy(xor_block, temp_block, BLOCK_SIZE);
	}

	/*now we have sixteen bytes ready to work on*/
	/*split it into two ULLONGs, left and right*/

	L = (ULLONG *)buffer;
	R = (ULLONG *)(buffer+8);

	/*Put the data into host byte order*/
	*L = ntohll (*L);
	*R = ntohll (*R);

	/*decrypt the data...*/
	for (i=rounds;i>=1;i--)
	{
		*R = rrotate(*R - S[2*i+1] , *L ) ^ *L;
		*L = rrotate(*L - S[2*i], *R) ^ *R;
	}
	*L -= S[0];
	*R -= S[1];

	/*Convert buffer back to network order*/
	*L = htonll(*L);
	*R = htonll(*R);

	return;
}
