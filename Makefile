VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"kaori\"
CFLAGS += -Wall -Wextra -std=c99 -pedantic

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -lmagic -ltls -lssl -lcrypto -lz

all: kaori

config.h:
	cp config.def.h $@

kaori: config.h src/kaori.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/kaori.c ${LIBS}
	strip $@

install:
	install kaori ${DESTDIR}${PREFIX}/bin/kaori

cert:
	openssl genrsa -out kaori.key 2048
	openssl req -new -key kaori.key -out kaori.csr
	openssl x509 -req -days 999999 -in kaori.csr -signkey kaori.key -out kaori.crt

push:
	got send
	git push

clean:
	rm -f kaori

again: clean all

