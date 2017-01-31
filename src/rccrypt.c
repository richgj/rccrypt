/*****************************************************************************
******************************************************************************
This program is part of the RC-Crypt suite
that implements rc5 128 bit block cipher.

Copyright (C) 2001-6 R.G.Jones, Eric Shorkey

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
Get all the data to do with the actual encoding and write it to shared
memory.
Fork and run rcc to do the actual work.
Wait for rcc to signal to say it is ready to rock and roll.
Remove the shared memory and exit.
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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <signal.h>

#include "rccrypt.h"

/************************************************************/
/*Global variables used by different subroutines*/
static BOOLEAN had_sigchld = FALSE;

/********************************************************************************/
/* Interrupt routine for the signal(s) we plan to get */
void sig_usr1()
{
	/*
	* This tells the parent that the data has been correctly read
	*/
	alarm(0);	/* cancels the alarm (if set)*/
}

void sig_alarm()
{
	/*
	* If the process is still running when the alarm arrives,
	* it is due to the child process failing for some reason.
	* The reason will have already been printed by the forked process
	*/
	bail("Alarm Signal raised");
}

void sig_chld()
{
	/*
	* Exit the parent as soon as the child is completed.
	* For some reason, sigchld can arrive BEFORE sigusr1.
	* If this happens, we need to kill the alarm or the
	* system will hang.
	*/
	alarm(0);
	/*
	* Also, if the sigchld arrives before sigusr1, and the -w
	* flag is used, it will hang.
	* Seta boolean to tell the system if we've already had the signal.
	*/
	had_sigchld = TRUE;
}

/********************************************************************************/
/* Main program begins here*/
/********************************************************************************/
int main(int argc, char **argv)
{
/********************************************************************************/
/*Declare all variables here*/
struct passwd *user_data;	/*will contain details of user data*/
int d;	/*used for determining command line options*/
FILE *keyfile;	/*used to input the key if it is in a file*/
char key_buffer[MAX_BYTES_IN_KEY + 1];	/*to hold key if input from a file*/
char my_cwd[500];	/*to hold the directory the program is started in*/

long num_chars_in_keystring;
char *e_var;	/*points to environment variable name*/
char *e_chars;	/*points to key string given via environment variable*/
char *k_chars;	/*points to key string given in command line*/
char *f_chars;  /*Points to file containing key*/
char *r_chars;	/*points to rounds string given in command line*/
char *infile;	/*points to filename if given on command line*/
char *outfile;	/*points to filename if given on command line*/
char *tail;	/*for char to number conversion checking*/
size_t rd_count;		/*how many items were reading/writing the stream*/
long rounds;	/*number of rounds required (0..255)*/
BOOLEAN pseudo_random;		/*To decide if each block is xor-ed with previous block*/

int shm_key;	/* shared memory key based on process pid */
RCC_OPTIONS *rcc_options;	/* holds the data to be written to the shared memory */
pid_t pid;	/* Variable to hold return value from fork */
BOOLEAN crypt;	/* To decide if we encrypt or decrypt */
BOOLEAN waiting;	/* Whether the parent should wait for it's child to complete */

/********************************************************************************/
/* CONNECT SIGNALS TO SUBROUTINES */
signal (SIGUSR1, sig_usr1);
signal (SIGALRM, sig_alarm);
signal (SIGCHLD, sig_chld);

/* Create a new process group so all children will be in a unique group */
setsid();

/********************************************************************************/
/*Set all variables etc to default/null values*/
	opterr = 0;
	num_chars_in_keystring=0;
	rounds=100;
	crypt = TRUE;
	e_chars=NULL;
	e_var = NULL;
	k_chars=NULL;
	f_chars=NULL;
	r_chars=NULL;
	keyfile=NULL;
	infile=NULL;
	outfile=NULL;
	pseudo_random=FALSE;
	waiting=FALSE;

/********************************************************************************/
/*Check out what options have been given and set variables*/
	while ((d = getopt (argc, argv, "dpe:k:f:r:i:o:vw")) != -1)
		switch (d)
		{
			case 'o':
				outfile=optarg;
				break;
			case 'p':
				pseudo_random = TRUE;
				break;
			case 'i':
				infile=optarg;
				break;
			case 'd':
				crypt = FALSE;
				break;
			case 'k':
				k_chars = optarg;
				break;
 			case 'e':
 				e_var = optarg;
 				e_chars = getenv(e_var);
				/* Remove the key so it isn't found in the child process's /proc */
				putenv(e_var);
				if (NULL == e_chars)
				{
					fprintf(stderr, "WARNING: Environment Variable '%s' not found.", e_var);
					fprintf(stderr, "\tWill look for key elsewhere\n");
				}
				fflush (NULL);
 				break;
			case 'f':
				f_chars = optarg;
				break;
			case 'r':
				r_chars = optarg;
				/*set the number of rounds*/
				errno=0;
				rounds=strtol(r_chars,&tail,10);
				if ((tail==r_chars)
					|| (errno)
					|| (rounds>255)
					|| (rounds<0))
					bail("ERROR: Rounds must be 0..255");
				break;
			case 'v':
				printf("RC-Crypt 1.7\n");
				exit(0);
				break;
			case 'w':
				waiting = TRUE;
				break;
			case '?':
				/*
				* The unknown case deliberate falls
				* through to the default case
				*/
			default:
				fprintf(stderr,"Usage:\n\t%s\t [-v] [-d] [-r rounds ] "
								"[ -k key | -f keyfile | -e env_var ] [ -i infilename ] "
								"[ -o outfilename ]\n\n",
								argv[0]);
				fprintf(stderr,"\nSee README file for further information\n");
				return 1;
		}

/* e_chars should over-ride k_chars, since it is more secure */
 	if( NULL != e_chars)
	{
 		k_chars = e_chars;
 	}
/********************************************************************************/
/* If a key has not been given, use the file given or ~/.rccrypt_key*/
	if (NULL == k_chars)
	{
		if (NULL == f_chars)
		{
			/*remember what directory we are in*/
			if (getcwd(my_cwd,500) != NULL)
			{
				/*find the user's home directory*/
				user_data=getpwuid(getuid());
				if (user_data == NULL)
					bail("Unable to determine user's home directory");

				if( user_data->pw_dir != NULL)
				{
					if (chdir(user_data->pw_dir))
						bail("Unable to change directory");
					keyfile = fopen(".rccrypt_key","r");
					/*return to the original directory*/
					if (chdir(my_cwd))
						bail("Unable to change directory");
				}
			}
			else
			{
				bail("Unable to determine current directory.");
			}
		}
		else
		{
			keyfile = fopen(f_chars,"r");
		}

		/*read in the key if the file exists*/
		if (keyfile != NULL)
		{
			/*
			* Don't use fgets() here in case the string in the file is
			* longer than the buffer - that would corrupt the stack
			* which is a BAD THING!
			*/
			rd_count = fread (key_buffer,1,MAX_BYTES_IN_KEY,keyfile);

			/*
			* Work backwards through the array replacing
			* End Of Line character(s) with End Of String
			* These are 0xA for unix, 0xD for MAC and 0xD,0xA for Windows
			*/
			while (--rd_count>=0)
			{
				if (0xA == (key_buffer[rd_count]) ||
					(0xD == key_buffer[rd_count]))
				{
					key_buffer[rd_count] = '\0';
				}
				else
				{
					/* to apply the case of no eol chars */
					key_buffer[rd_count+1] = '\0';
					break;
				}
			}
			/*set the k_chars to point to the buffer*/
			k_chars = key_buffer;
			/*close the file*/
			fclose(keyfile);
		}
		/*note - if gets to here without creating key, an error will occur*/
	}
/********************************************************************************/
/*set the number of chars in the key*/
	if(k_chars != NULL)
	{
		num_chars_in_keystring=strlen(k_chars);
		if (num_chars_in_keystring > 64)
		{
			num_chars_in_keystring = 64;
		}
		else if (0 == num_chars_in_keystring)
		{
			bail("You cannot have a zero length key");
		}
	}
	else
	{
		bail("You must supply a key");
	}

/********************************************************************************/
/* open the shared memory area based on the pid of this process */

/* first, get a key to use */
	shm_key = shmget(getpgrp(), sizeof(RCC_OPTIONS), IPC_CREAT|0600);

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

/********************************************************************************/
/* fill the rcc_options structure */
	rcc_options->length = num_chars_in_keystring;
	rcc_options->rounds = rounds;
	rcc_options->crypt = crypt;
	rcc_options->pseudo = pseudo_random;

	/* copy the key */
	strncpy(rcc_options->key, k_chars, MAX_BYTES_IN_KEY + 1);

	/* copy the infile */
	if (NULL == infile)
	{
		/* we will be using stdin */
		sprintf(rcc_options->infile, "STDIN");
	}
	else
	{
		strncpy(rcc_options->infile, infile, MAX_FILE);
		rcc_options->infile[MAX_FILE] = '\0';
	}

	/* copy the outfile */
	if (NULL == outfile)
	{
		/* we will be using stdin */
		sprintf(rcc_options->outfile, "STDOUT");
	}
	else
	{
		strncpy(rcc_options->outfile, outfile, MAX_FILE);
		rcc_options->outfile[MAX_FILE] = '\0';
	}

/* set an alarm to wait for the child process */
	alarm(5);

/* fork a new process */

	pid = fork();

	if (-1 == pid)
	{
		bail ("ERROR: Unable to fork");
	}

	if (0 == pid)
	{
		/* this is the child */
		/* rcc must be found in the PATH */
		execlp("rcc", "rcc", NULL);
		/* note - it should never return from this call */
		bail("Failed to start rcc as child process");
	}

/* continue as the parent */

/*
* Wait for a signal from the child to say it has the data
* Check the sigusr1 hasn't already reset the previous alarm.
*/
	if (0 == alarm(5)) /* alarm time left = 0 or not set */
	{
		/* The sigusr1 signal has already arrived */
		alarm(0);
	}
	else
	{
		/* Wait for the sigusr1 */
		pause();
	}

/* The child has read the data now */
	memset(rcc_options, 0, sizeof(RCC_OPTIONS));
	shmdt((void *)rcc_options);

/* Wait for the child process to complete before exiting */
	if ((waiting) && (!had_sigchld))
	{
		pause();
	}

	return 0;

}
