VERSION = 0.3
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"kaori\"
CFLAGS += -Wall -Wextra -std=c99 -pedantic -O2

PREFIX ?= /usr/local
MANDIR ?= /share/man

LIBS += -ltls -lssl -lcrypto -lz

all: kaori

config.h:
	cp config.def.h $@

kaori: config.h src/heart.c src/kaori.c
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ src/kaori.c ${LIBS}
	strip $@

test: src/test.c src/heart.c
	${CC} ${CFLAGS} -o test src/test.c
	./test
	rm -f test

install:
	install kaori ${DESTDIR}${PREFIX}/bin/kaori

cert:
	openssl genrsa -out kaori.key 2048
	openssl req -new -key kaori.key -out kaori.csr
	openssl x509 -req -days 999999 -in kaori.csr -signkey kaori.key -out kaori.crt

README.md: README.gmi
	sisyphus -f markdown <README.gmi >README.md

doc: README.md

push: test
	got send
	git push github

clean:
	rm -f kaori test

again: clean all

release: push
	git push github --tags
