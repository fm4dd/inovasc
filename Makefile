CC=gcc
CFLAGS= -O3 -Wall -g -I../cgic205
AR=ar
LIBS= -lcgic

BASEDIR=/srv/app/std-root/frank4dd.com

HTMDIR=${BASEDIR}/inovasc
STLDIR=${BASEDIR}/inovasc/style
IMGDIR=${BASEDIR}/inovasc/images
CGIDIR=${BASEDIR}/inovasc/cgi-bin
CRTDIR=${BASEDIR}/inovasc/etc
TPLDIR=${BASEDIR}/inovasc/templates
RESDIR=${BASEDIR}/inovasc/results

ALLHTM=html/index.htm
ALLSTL=style/style.css
ALLIMG=images/*.gif
ALLCRT=etc/*
ALLTPL=templates/*

all:
	cd src && ${MAKE}
	cd demo-src && ${MAKE}

inovasc:
	cd src && ${MAKE}

demo:
	cd demo-src && ${MAKE}

install:
	cp ${ALLHTM} ${HTMDIR}
	cp ${ALLSTL} ${STLDIR}
	cp ${ALLIMG} ${IMGDIR} 
	cp ${ALLCRT} ${CRTDIR}
	cp ${ALLTPL} ${TPLDIR}
	cd src && ${MAKE} install

install-demo:
	cd demo-src && ${MAKE} install

clean:
	cd src && ${MAKE} clean
	cd demo-src && ${MAKE} clean
