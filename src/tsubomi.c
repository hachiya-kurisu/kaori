// see us after school for copyright and license details

#define _PR_HAVE_LARGE_OFF_T

#include <glob.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <magic.h>
#include <tls.h>

#include "tsubomi.h"

static magic_t magic;

void encode(unsigned char *s, char *enc) {
  char skip[256] = { 0 };
  unsigned int i;
  for(i = 0; i < 256; i++)
    skip[i] = isalnum(i) || i == '~'||i == '-'||i == '.'||i == '_' ? i : 0;

  for(; *s; s++) {
    if(skip[(int) *s]) sprintf(enc, "%c", skip[(int) *s]), ++enc;
    else {
      sprintf(enc, "%%%02x", *s);
      while (*++enc);
    }
  }
}

int decode(char *src, char *dst) {
  int pos = 0;
  char buffer[3] = { 0 };
  unsigned int decoded;

  while(src && *src) {
    buffer[pos] = *src;

    if(pos == 2) {
      if(buffer[0] == '%' && isxdigit(buffer[1]) && isxdigit(buffer[2])) {
        sscanf(buffer, "%%%2x", &decoded);
        *dst++ = decoded;
        memset(buffer, 0, 3);
        pos = 0;
      } else {
        *dst++ = buffer[0];
        memmove(buffer, &buffer[1], 2);
        buffer[2] = 0;
      }
    } else {
      pos++;
    }
    src++;
  }
  char *rest = buffer;
  while(pos--) *dst++ = *rest++;
  *dst++ = '\0';
  return 0;
}

int header(int status, char *meta) {
  char buffer[1026];
  int len = snprintf(buffer, 1026, "%d %s\r\n", status, meta ? meta : "");
  config.tls ? tls_write(config.tls, buffer, len) : write(1, buffer, len);
  return 1;
}

int servefile(char *path) {
  int fd = open(path, O_RDONLY);
  if(!fd) return header(51, "not found");

  char *mime = (char *) magic_file(magic, path);
  header(20, !strcmp(mime, "text/plain") ? "text/gemini" : mime);

  char buffer[BUFSIZ] = { 0 };
  ssize_t l;
  while((l = read(fd, buffer, BUFSIZ)) != 0) {
    if(l > 0) {
      if(config.tls) {
        tls_write(config.tls, buffer, l);
      } else {
        write(1, buffer, l);
      }
    }
  }
  close(fd);
  fflush(stdout);
  return 0;
}

int list(char *current) {
  struct stat fs = { 0 };
  stat(config.index, &fs);

  if(S_ISREG(fs.st_mode))
    return servefile(config.index);

  header(20, "text/gemini");
  glob_t res;
  if(glob("*", GLOB_MARK, 0, &res)) {
    char *str = "(*^o^*)\r\n";
    int len = strlen(str);
    config.tls ? tls_write(config.tls, str, len) : write(1, str, len);

    return 0;
  }
  char *path;
  for(size_t i = 0; i < res.gl_pathc; i++) {
    path = res.gl_pathv[i];

    char ecurrent[(strlen(current) * 3 + 1)];
    encode((unsigned char *) current, ecurrent);

    char epath[(strlen(path) * 3 + 1)];
    encode((unsigned char *) path, epath);

    int len = strlen(epath);
    if(epath[len - 1] == '~') continue;
    if(strstr(epath, ".gmi") == &epath[len - 4]) len -= 4;

    char buffer[BUFSIZ * 32] = { 0 };

    int l = snprintf(buffer, BUFSIZ * 32, "=> %s/%.*s %.*s\n",
        ecurrent, len, epath, len, epath);
    config.tls ? tls_write(config.tls, buffer, l) : write(1, buffer, l);
  }
  return 0;
}

int cgi(char *path, char *data, char *query) {
  setenv("GEMINI_PATH", path ? path : "", 1);
  setenv("GEMINI_DATA", data ? data : "", 1);
  setenv("GEMINI_QUERY", query ? query : "", 1);

  int fd[2];
  pipe(fd);

  pid_t pid = fork();
  if(!pid) {
    dup2(fd[1], 1);
    close(fd[0]);
    char *argv[] = { path, data, query };
    execv(path, argv);
  }
  close(fd[1]);

  char buffer[BUFSIZ * 32] = { 0 };
  ssize_t l;
  while((l = read(fd[0], buffer, BUFSIZ * 32)) > 0) {
    config.tls ? tls_write(config.tls, buffer, l) : write(1, buffer, l);
  }
  wait(0);

  return 0;
}

int serve(char *current, char *remaining, char *query) {
  if(!remaining || !strcspn(remaining, "/"))
    return list(current);

  char *p = strsep(&remaining, "/");

  struct stat fs = { 0 };
  stat(p, &fs);

  if(S_ISREG(fs.st_mode) && fs.st_mode & S_IXOTH)
    return cgi(p, remaining, query);

  if(S_ISDIR(fs.st_mode)) {
    sprintf(current + strlen(current), "/%s", p);
    if(chdir(p)) return header(51, "not found");
    return serve(current, remaining, query);
  }
  if(S_ISREG(fs.st_mode)) return servefile(p);

  char inferred[LINE_MAX];
  sprintf(inferred, "%s.gmi", p);
  memset(&fs, 0, sizeof(fs)); 
  stat(inferred, &fs);
  if(S_ISREG(fs.st_mode)) return servefile(inferred);

  return header(51, "not found");
}

void init() {
  magic = magic_open(MAGIC_NONE);
  magic_load(magic, 0);
  magic_setflags(magic, MAGIC_MIME_TYPE);
}

int tsubomi(char *raw) {
  char url[1026] = { 0 };
  char path[1026] = { 0 };
  char query[1026] = { 0 };

  char *domain = 0, *port = 0, *rawpath = 0, *rawquery = 0;

  for(int i = (int) strlen(raw); i >= 0; i--)
    if(raw[i] == '\n' || raw[i] == '\r') raw[i] = '\0';

  sprintf(url, "%s", raw);
  domain = url;

  if(strstr(domain, "gemini://") == domain) domain += 9;
  else if(strstr(domain, "gemini+stream://") == domain) domain += 16;

  if(domain && (rawpath = strchr(domain, '/'))) *rawpath++ = '\0';
  if(rawpath && (rawquery = strchr(rawpath, '?'))) *rawquery++ = '\0';
  if(domain && (port = strchr(domain, ':'))) *port++ = '\0';

  char *peer = getenv("TSUBOMI_PEERADDR");
  if(config.log) {
    FILE *fp = fopen(config.log, "a");
    if(fp) {
      fprintf(fp, "%s:%s\n", peer, raw);
      fclose(fp);
    }
  }
  fprintf(stderr, "%s:%s\n", peer, raw);

  for(int i = 0; domains[i]; i++) {
    if(strstr(domain, domains[i]) == domain) break;
    return header(51, "not found");
  }

  if(chdir(domain)) return header(51, "not found");
  decode(rawpath, path);
  decode(rawquery, query);

  if(strstr(path, "..")) return header(51, "not found");
  if(strstr(path, "//")) return header(51, "not found");

  char current[2048] = "";
  return serve(current, path, query);
}

