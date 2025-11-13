#ifndef GEMINI_H
#define GEMINI_H

#define HEADER 1028
#define BUFFER 65536

struct request {
  struct tls *tls;
  time_t time;
  char url[HEADER];
  char *cwd, *path, *query;
  int certified, expired, ongoing;
  char *ip, *hash;
  char cn[128], uid[128], email[128], org[128];
};

extern const char *fallback;

int gemini(struct request *req, char *url);

#endif
