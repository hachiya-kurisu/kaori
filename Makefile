VERSION = 0.2
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

kaori: config.h src/kaori.c
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ src/kaori.c ${LIBS}
	strip $@

install:
	install kaori ${DESTDIR}${PREFIX}/bin/kaori

cert:
	openssl genrsa -out kaori.key 2048
	openssl req -new -key kaori.key -out kaori.csr
	openssl x509 -req -days 999999 -in kaori.csr -signkey kaori.key -out kaori.crt

README.md: README.gmi
	sisyphus -f markdown <README.gmi >README.md

doc: README.md

push:
	got send
	git push github

clean:
	rm -f kaori

again: clean all

release: push
	git push github --tags
