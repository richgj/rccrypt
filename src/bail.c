/*****************************************************************************
******************************************************************************
This program is part of the RC-Crypt suite
that implements rc5 128 bit block cipher.

Copyright (C) 2001-2 R.G.Jones

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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/********************************************************************************/
/*Exit the program on abnormal errors*/
void bail (char *c)
{
	if (errno != 0)
		perror(c);
	else
		fprintf(stderr, "%s\n", c);
	exit(1);
}
