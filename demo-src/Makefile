CC=gcc
CFLAGS= -O3 -Wall -I/home/openssl/include
LIBS= -L/home/openssl/lib -lssl -lcrypto
AR=ar

BINDIR=../demo-src

ALLBIN=otp-demo-getprefs otp-demo-dumpprefs otp-demo-startscan

all: ${ALLBIN}

install: 
	strip ${ALLBIN}
	cp ${ALLBIN} ${BINDIR}
	@echo ${ALLBIN} installed in ${BINDIR}.

clean:
	rm -f *.o ${ALLBIN}

otp-demo-getprefs: otp-demo-getprefs.o
	$(CC) ${LIBS} otp-demo-getprefs.o -o otp-demo-getprefs

otp-demo-dumpprefs: otp-demo-dumpprefs.o
	$(CC) ${LIBS} otp-demo-dumpprefs.o -o otp-demo-dumpprefs

otp-demo-startscan: otp-demo-startscan.o
	$(CC) ${LIBS} otp-demo-startscan.o -o otp-demo-startscan
