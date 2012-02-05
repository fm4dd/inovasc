CC=gcc
# SuSe Linux doesn't need the includes because
# OpenSSL is in the standard search path /usr/lib
# Solaris or other locations of OpenSSL needs the include path
CFLAGS= -O3 -Wall -g
LIBS= -lcgic -lssl -lcrypto
AR=ar

CGIDIR=/srv/www/std-root/frank4dd.com/sw/inovasc/cgi-bin

ALLCGI=help.cgi scanlogin.cgi scanconfig.cgi scanprocess.cgi scanresults.cgi about.cgi scantemplates.cgi scanverify.cgi

all: ${ALLCGI}

install: 
	strip ${ALLCGI}
	cp ${ALLCGI} ${CGIDIR}
	@echo ${ALLCGI} installed in ${CGIDIR}.

clean:
	rm -f *.o *.cgi

help.cgi: help.o pagehead.o pagefoot.o handle_error.o
	$(CC) ${LIBS} help.o pagehead.o pagefoot.o handle_error.o -o help.cgi

about.cgi: about.o pagehead.o pagefoot.o handle_error.o
	$(CC) ${LIBS} about.o pagehead.o pagefoot.o handle_error.o -o about.cgi

scanlogin.cgi: scanlogin.o handle_error.o
	$(CC) ${LIBS} scanlogin.o pagehead.o pagefoot.o handle_error.o -o scanlogin.cgi

scanconfig.cgi: scanconfig.o inovasc.o handle_error.o pagehead.o pagefoot.o template.o
	$(CC) ${LIBS} scanconfig.o \
                      template.o \
                      inovasc.o \
                      pagehead.o pagefoot.o \
                      handle_error.o -o scanconfig.cgi

scanprocess.cgi: scanprocess.o inovasc.o handle_error.o pagehead.o pagefoot.o template.o
	$(CC) ${LIBS} scanprocess.o \
                      template.o \
                      inovasc.o \
                      pagehead.o pagefoot.o \
                      handle_error.o -o scanprocess.cgi

scanresults.cgi: scanresults.o inovasc.o handle_error.o pagehead.o pagefoot.o
	$(CC) ${LIBS} scanresults.o \
                      inovasc.o \
                      pagehead.o pagefoot.o \
                      handle_error.o -o scanresults.cgi

scantemplates.cgi: template.o scantemplates.o inovasc.o handle_error.o pagehead.o pagefoot.o
	$(CC) ${LIBS} template.o \
                 scantemplates.o \
                      inovasc.o \
                      pagehead.o pagefoot.o \
                      handle_error.o -o scantemplates.cgi

scanverify.cgi: scanverify.o inovasc.o handle_error.o pagehead.o pagefoot.o template.o
	$(CC) ${LIBS} scanverify.o \
                      template.o \
                      inovasc.o \
                      pagehead.o pagefoot.o \
                      handle_error.o -o scanverify.cgi
