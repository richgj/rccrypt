#define your compiler
CC = gcc

#define the source directory
src=src/

#define hfiles that will cause rebuilding
#nb not the best solution if there are lots of files!
#(changing one .h file will recompile everything)
II=include/
HFILES = $(II)rccrypt.h

#define your objects
RCCRYPT_BG_OBJECTS = $(src)rccrypt_bg.o $(src)bail.o $(src)random_char.o \
	$(src)get_remainder.o $(src)rotate.o $(src)debug.o

RCCRYPT_OBJECTS = $(src)rccrypt.o $(src)bail.o $(src)debug.o

#define Compiler flags
CFLAGS = -Wall -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE

#define include directories
INC = -I$(II)

#define debug level (-DDEBUG = on, -DNDEBUG = off)
DD = -DNDEBUG

#define optimization level(-O1/2/3)
OO = -O1

#define link flags
LDFLAGS =

all : rccrypt rccrypt_bg

rccrypt : $(RCCRYPT_OBJECTS)
	$(CC) $(RCCRYPT_OBJECTS) $(LDFLAGS) -o rccrypt

rccrypt_bg : $(RCCRYPT_BG_OBJECTS)
	$(CC) $(RCCRYPT_BG_OBJECTS) $(LDFLAGS) -o rccrypt_bg


#define a default compilation thing
%.o : %.c $(HFILES)
	$(CC) -c $(CFLAGS) $(INC) $(DD) $(OO) $< -o $@

#clean up routine
.PHONY :
clean :
	-rm -f $(src)*.o
