VERSION = 0.5
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"kaori\"
CFLAGS += -Wall -Wextra -std=c99 -pedantic -Wformat=2
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -Wshadow -Wcast-align -Wstrict-prototypes
CFLAGS += -Wwrite-strings -Wconversion -Wformat-security
CFLAGS += -Wmissing-prototypes -Wold-style-definition

LINTFLAGS += --enable=all --inconclusive --language=c --library=posix
LINTFLAGS += --quiet --suppress=missingIncludeSystem
LINTFLAGS += --suppress=getpwnamCalled --suppress=getgrnamCalled

PREFIX ?= /usr/local

LIBS += -ltls -lssl -lcrypto -lz

.PHONY: all install lint doc push clean again release

all: kaori

kaori: src/gemini.c src/kaori.c
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ src/gemini.c src/kaori.c ${LIBS}

install:
	install -d ${DESTDIR}${PREFIX}/bin
	install -d ${DESTDIR}/etc/rc.d
	install -m 755 kaori ${DESTDIR}${PREFIX}/bin/kaori
	install -m 555 kaori.rc ${DESTDIR}/etc/rc.d/kaori

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/kaori
	rm -f ${DESTDIR}/etc/rc.d/kaori

lint:
	cppcheck ${LINTFLAGS} src/*.c

README.md: README.gmi
	sisyphus -f markdown <README.gmi >README.md

doc: README.md

test: src/test.c src/gemini.c
	${CC} ${CFLAGS} ${LDFLAGS} -o test src/test.c ${LIBS}
	./test
	rm -f test

cert:
	openssl genrsa -out kaori.key 2048
	openssl req -new -key kaori.key -out kaori.csr
	openssl x509 -req -days 999999 -in kaori.csr -signkey kaori.key -out kaori.crt

push: test
	got send
	git push github

clean:
	rm -f kaori

again: clean all

release: push
	git push github --tags
