# rccrypt
RC-Crypt keeps your data safe. It is an easy to use command line program that encrypts your data.

Copyright (C) 2001-17 R.G.Jones, Eric Shorkey

## How to use this program.

1. Compile it.
	A Makefile has been created, that will allow you to build it using
				make
	If you wish to add options, feel free to do so :-)

2.	Copy both the rccrypt and the rccrypt_bg
	program to somewhere you can run it.
	Find the places you could copy it to using
		echo $PATH
	(It is likely you will need root access for most of these.)

3. Use it.
	rccrypt will encrypt or decrypt the input given to it according
	to the rc5 Algorithm as described by RSA Laboratories.

	The syntax is as follows:

	rccrypt [-d] [-p] [ -r rounds] [-k key | -f file | -e env_var] [-i infile] [-o outfile] [-w]

Further help can be found using the man file.
Try "man -M man rccrypt" in this directory, or copy the rccrypt.1
file to one of the directories found by typing "echo $MANPATH".
