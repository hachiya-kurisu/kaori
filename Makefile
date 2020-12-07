VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"kaori\"
CFLAGS += -Os -Wall -Wextra -std=c99 -pedantic -static

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -lmagic -ltls -lssl -lz -lcrypto

all: kaori

config.h:
	cp config.def.h $@

libkaori.a: src/kaori.c src/kaori.h
	${CC} ${CFLAGS} ${LDFLAGS} -c src/kaori.c -o kaori.o
	ar -cvqs libkaori.a kaori.o

kaori: libkaori.a config.h src/main.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/main.c -lkaori ${LIBS}

install:
	install kaori ${DESTDIR}${PREFIX}/bin/kaori
	install libkaori.a ${DESTDIR}${PREFIX}/lib/libkaori.a

generate-cert:
	openssl genrsa -out /etc/ssl/private/gemini.key 4096
	openssl req -new -key /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.csr
	openssl x509 -req -days 36500 -extfile server.ext \
		-in /etc/ssl/gemini.csr -signkey /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.crt

clean:
	rm -f kaori kaori.o libkaori.a

again: clean all

