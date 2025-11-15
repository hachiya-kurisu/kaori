#ifndef GEMINI_H
#define GEMINI_H

#define HEADER 1028
#define BUFFER 65536

#ifndef VERSION
#define VERSION "unknown"
#endif

int gemini(struct tls *tls, char *url, int shared);

#endif
