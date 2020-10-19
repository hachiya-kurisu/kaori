VERSION = 0.1
OS != uname -s

-include Makefile.$(OS)

CFLAGS += -DVERSION=\"${VERSION}\"
CFLAGS += -DNAME=\"tsubomi\"
CFLAGS += -Os -Wall -Wextra -std=c99 -pedantic

PREFIX ?= /usr
MANDIR ?= /share/man

LIBS += -lmagic

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

clean:
	rm -f tsubomi tsubomi.o libtsubomi.a

again: clean all

