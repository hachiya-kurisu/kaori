VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"tsubomi\"
CFLAGS += -Os -Wall -Wextra -std=c99 -pedantic -static

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -lmagic -ltls -lssl -lz -lcrypto

all: tsubomi

config.h:
	cp config.def.h $@

libtsubomi.a: src/tsubomi.c src/tsubomi.h
	${CC} ${CFLAGS} ${LDFLAGS} -c src/tsubomi.c -o tsubomi.o
	ar -cvqs libtsubomi.a tsubomi.o

tsubomi: libtsubomi.a config.h src/main.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/main.c -ltsubomi ${LIBS}

install:
	install tsubomi ${DESTDIR}${PREFIX}/bin/tsubomi
	install libtsubomi.a ${DESTDIR}${PREFIX}/lib/libtsubomi.a

generate-cert:
	openssl genrsa -out /etc/ssl/private/gemini.key 4096
	openssl req -new -key /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.csr
	openssl x509 -req -days 36500 -extfile server.ext \
		-in /etc/ssl/gemini.csr -signkey /etc/ssl/private/gemini.key \
		-out /etc/ssl/gemini.crt

clean:
	rm -f tsubomi tsubomi.o libtsubomi.a

again: clean all

