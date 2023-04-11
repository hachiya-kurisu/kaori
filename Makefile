VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"kaori\"
CFLAGS += -Wall -Wextra -std=c99 -pedantic -static

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
	openssl genrsa -out /etc/ssl/private/gemini.key 2048
	openssl req -new -key /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.csr
	openssl x509 -req -days 2500000 -extfile server.ext \
		-in /etc/ssl/gemini.csr -signkey /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.crt

clean:
	rm -f kaori

again: clean all

