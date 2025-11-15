#ifndef GEMINI_H
#define GEMINI_H

#define HEADER 1028
#define BUFFER 65536

#ifndef VERSION
#define VERSION "unknown"
#endif

struct identity {
  int provided;
  char *hash, *subject;
  char cn[128], uid[128], email[128], org[128];
};

typedef void (*put)(void *ctx, char *buf, int len);
typedef void (*ask)(void *ctx, struct identity *id);

int gemini(put out, ask who, void *ctx, char *url, int shared);

#endif
