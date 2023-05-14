CC = gcc
CFLAGS = -Wall -Wextra -Werror
MFLAGS = -lssl -lcrypto

all: stnc

stnc: stnc.c
	$(CC) $(CFLAGS) stnc.c -o stnc $(MFLAGS)


clean:
	rm -f stnc

