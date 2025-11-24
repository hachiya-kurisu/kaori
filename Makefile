VERSION = 0.6
OS != uname -s
KEY ?= ~/.signify/blekksprut-pkg.sec

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
MANDIR ?= /usr/local/man

LIBS += -ltls -lssl -lcrypto -lz

.PHONY: all install lint doc push clean again release sign pkg

all: kaori

kaori: src/gemini.c src/kaori.c Makefile
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ src/gemini.c src/kaori.c ${LIBS}
	strip $@

install:
	install -d ${DESTDIR}${PREFIX}/bin
	install -d ${DESTDIR}/etc/rc.d
	install -d ${DESTDIR}${MANDIR}/man8
	install -m 644 kaori.8 ${DESTDIR}${MANDIR}/man8/kaori.8
	install -m 755 kaori ${DESTDIR}${PREFIX}/bin/kaori
	install -m 555 kaori.rc ${DESTDIR}/etc/rc.d/kaori

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/kaori
	rm -f ${DESTDIR}${MANDIR}/man8/kaori.8
	rm -f ${DESTDIR}/etc/rc.d/kaori

pkg: kaori
	@[ `uname` = OpenBSD ] || { echo "requires openbsd"; exit 1; }
	rm -rf /tmp/pkg
	make install DESTDIR=/tmp/pkg PREFIX=/usr/local
	pkg_create \
		-D COMMENT="a neon-drenched gemini server" \
		-D MAINTAINER="kurisu@blekksprut.net" \
		-D HOMEPAGE="https://blekksprut.net/kaori" \
		-D FULLPKGPATH=net/kaori \
		-D FULLPKGNAME=kaori-${VERSION} \
		-d pkg/DESCR \
		-f pkg/PLIST \
		-B /tmp/pkg \
		-p /usr/local \
		kaori-${VERSION}.tgz

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
	rm -rf signed/

again: clean all

sign: pkg
	mkdir -p signed/
	pkg_sign -s signify2 -s ${KEY} -o signed/ kaori-${VERSION}.tgz

release:
	if [ `uname` = OpenBSD ]; then \
		$(MAKE) sign && \
		mkdir -p /var/www/blekksprut.net/pkg && \
		cp signed/kaori-${VERSION}.tgz /var/www/blekksprut.net/pkg/; \
	fi
	git push github --tags
