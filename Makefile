VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"tsubomi\"
CFLAGS += -Os -Wall -Wextra -std=c99 -pedantic

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -lmagic -ltls

all: tsubomi tsubomi-test

config.h:
	cp config.def.h $@

libtsubomi.a: src/tsubomi.c src/tsubomi.h
	${CC} ${CFLAGS} ${LDFLAGS} -c src/tsubomi.c -o tsubomi.o
	ar -cvqs libtsubomi.a tsubomi.o

tsubomi: libtsubomi.a config.h src/main.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/main.c -ltsubomi ${LIBS}

tsubomi-test: libtsubomi.a config.h src/tsubomi-test.c
	${CC} ${CFLAGS} ${LDFLAGS} -L. -o $@ src/tsubomi-test.c -ltsubomi ${LIBS}

install:
	install tsubomi ${DESTDIR}${PREFIX}/bin/tsubomi
	install libtsubomi.a ${DESTDIR}${PREFIX}/lib/libtsubomi.a

generate-cert:
	openssl genrsa -out /var/gemini/gemini.key 4096
	openssl req -new -key /var/gemini/gemini.key \
		-out /var/gemini/gemini.csr
	openssl x509 -req -days 365 -extfile server.ext \
		-in /var/gemini/gemini.csr -signkey /var/gemini/gemini.key \
		-out /var/gemini/gemini.crt

clean:
	rm -f tsubomi tsubomi-test tsubomi.o libtsubomi.a

again: clean all

