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
/************************************************************/
/*Stuff used if we are in debug mode*/
#include "stdio.h"
#include "rccrypt.h"

#ifdef DEBUG
void uprint (char *name, ULLONG thing)
{
int i;
char *cptr ;

	cptr = (char *) &thing;

	printf("%s ",name);
	for(i=0; i<8; i++)
		printf("%c:",*cptr++);
	printf("\n");
}
#endif
