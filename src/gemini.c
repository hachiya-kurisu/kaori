#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <glob.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "gemini.h"

static struct request {
  put out;
  void *ctx;
  time_t time;
  char *cwd, *path, *query;
  int ongoing;
} req;

static struct identity id = {0};

static const char *types[][2] = {
  {".gmi", "text/gemini"},
  {".txt", "text/plain"},
  {".jpg", "image/jpeg"},
  {".jpeg", "image/jpeg"},
  {".png", "image/png"},
  {".gif", "image/gif"},
  {".jxl", "image/jxl"},
  {".webp", "image/webp"},
  {".mp3", "audio/mpeg"},
  {".m4a", "audio/mp4"},
  {".mp4", "video/mp4"},
  {".wav", "audio/wav"},
  { 0, 0 },
};

const char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789"
                    "-._~:/?#[]@!$&'()*+,;=%\r\n";

const char *fallback = "application/octet-stream";

static int dig(const char *path, char *dst, const char *needle) {
  FILE *fp = fopen(path, "r");
  if(!fp) return -1;
  char buf[LINE_MAX];
  int retval = 0;
  while(fgets(buf, LINE_MAX, fp)) {
    buf[strcspn(buf, "\r\n")] = 0;
    if(needle && !strcmp(buf, needle)) {
      retval = 1;
      break;
    } else if(dst) {
      strlcpy(dst, buf, LINE_MAX);
      break;
    }
  }
  fclose(fp);
  return retval;
}

static const char *mime(const char *path) {
  static char type[PATH_MAX] = {0};

  char override[PATH_MAX] = {0};
  snprintf(override, PATH_MAX, ".%s.mime", path);
  if(dig(override, type, 0) != -1) return type;

  const char *ext = strchr(path, '.');
  if(!ext)
    return fallback;

  for (int i = 0; types[i][0] != 0; i++) {
    if(!strcasecmp(ext, types[i][0])) {
      return types[i][1];
    }
  }
  return fallback;
}

static void encode(const char *src, char *dst) {
  unsigned char *s = (unsigned char *) src;
  if(!strlen((char *) s)) {
    dst[0] = '\0';
    return;
  }
  static char skip[256] = {0};
  if(!skip[(int) '-']) {
    for(int i = 0; i < 256; i++)
      skip[i] = strchr(valid, i) ? (char)i : 0;
  }
  for(; *s; s++) {
    if(skip[(int) *s]) snprintf(dst, 2, "%c", skip[(int) *s]), ++dst;
    else {
      int bytes = snprintf(dst, 4, "%%%02x", *s);
      if(bytes <= 0) {
        *dst = '\0';
        return;
      }
      dst += bytes;
    }
  }
  *dst = '\0';
}

static int decode(const char *src, char *dst) {
  int pos = 0;
  char buf[3] = {0};
  unsigned int decoded;
  while(src && *src) {
    buf[pos] = *src;
    if(pos == 2) {
      if(buf[0] == '%' && isxdigit(buf[1]) && isxdigit(buf[2])) {
        sscanf(buf, "%%%2x", &decoded);
        *dst++ = (char)decoded;
        memset(buf, 0, 3);
        pos = 0;
      } else {
        *dst++ = buf[0];
        memmove(buf, &buf[1], 2);
        buf[2] = 0;
      }
    } else {
      pos++;
    }
    src++;
  }
  const char *rest = buf;
  while(pos--) *dst++ = *rest++;
  *dst++ = '\0';
  return 0;
}

static void die(int eval, const char *msg) {
  syslog(LOG_ERR, "%s", msg);
  _exit(eval);
}

static int header(int status, const char *meta) {
  if(req.ongoing) return 1;
  if(strlen(meta) > 1024) return 1;
  char buf[HEADER];
  int len = snprintf(buf, HEADER, "%d %s\r\n", status, *meta ? meta : "");
  req.out(req.ctx, buf, len);
  req.ongoing = 1;
  return 0;
}

static void transfer(int fd) {
  char buf[BUFFER] = {0};
  ssize_t len;
  while((len = read(fd, buf, BUFFER)) > 0)
    req.out(req.ctx, buf, len);
  if(len == -1) die(1, "read failed");
}

static int file(const char *path) {
  int fd = open(path, O_RDONLY);
  if(fd == -1) return header(51, "not found");
  const char *type = mime(path);
  header(20, type);
  transfer(fd);
  close(fd);
  return 0;
}

static void humansize(double bytes, char *buffer, size_t len) {
  const char *units[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
  unsigned int i = 0;
  while (bytes >= 1024.0 && i < (sizeof(units) / sizeof(units[0])) - 1) {
    bytes /= 1024.0;
    i++;
  }
  snprintf(buffer, len, "%.1f %s", bytes, units[i]);
}

static void entry(char *path) {
  struct stat sb = {0};
  if(stat(path, &sb) == -1) return;

  char safe[strlen(path) * 3 + 1];
  encode(path, safe);

  const char *type;
  if (S_ISDIR(sb.st_mode)) {
    type = "directory";
  } else {
    type = mime(path);
  }

  char size[64];
  humansize((double)sb.st_size, size, sizeof(size));

  char s[PATH_MAX * 5];
  int len = snprintf(s, sizeof(s), "=> %s %s [%s %s]\n", safe, path, type, size);
  req.out(req.ctx, s, len);
}

static int ls(void) {
  struct stat sb = {0};
  int ok = stat("index.gmi", &sb);
  if(!ok && S_ISREG(sb.st_mode))
    return file("index.gmi");
  header(20, "text/gemini");
  glob_t res;
  if(glob("*", GLOB_MARK, 0, &res)) {
    const char *empty = "(*^o^*)\r\n";
    req.out(req.ctx, empty, (ssize_t)strlen(empty));
    return 0;
  }
  for(size_t i = 0; i < res.gl_pathc; i++) {
    entry(res.gl_pathv[i]);
  }
  globfree(&res);
  return 0;
}

static int cgi(char *path) {
  setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
  setenv("QUERY_STRING", req.query ? req.query : "", 1);
  setenv("PATH_INFO", req.path ? req.path : "", 1);
  setenv("SCRIPT_NAME", path ? path : "", 1);
  setenv("SERVER_PORT", "1965", 1);
  setenv("SERVER_SOFTWARE", "槇村香/" VERSION, 1);
  setenv("SERVER_PROTOCOL", "gemini", 1);
  if(id.provided) {
    setenv("AUTH_TYPE", "Certificate", 1);
    setenv("REMOTE_USER", *id.cn ? id.cn : "", 1);
    setenv("TLS_CLIENT_HASH", id.hash, 1);
  }

  int fd[2];
  if(pipe(fd) == -1)
    die(1, "pipe failed");

  pid_t pid = fork();
  if(pid == -1) die(1, "fork failed");

  if(!pid) {
    dup2(fd[1], 1);
    close(fd[0]);
    char *argv[] = { path, 0 };
    alarm(30);
    execv(path, argv);
    _exit(1);
  }
  close(fd[1]);

  char buf[BUFFER] = {0};
  ssize_t len;
  while((len = read(fd[0], buf, BUFFER)) > 0)
    req.out(req.ctx, buf, len);

  close(fd[0]);
  kill(pid, SIGKILL);
  int status;
  waitpid(pid, &status, 0);
  return 0;
}

static int route(void) {
  if(!dig(".authorized", 0, id.hash))
    return header(id.provided ? 61 : 60, "unauthorized");

  if(!req.path)  {
    char url[HEADER];
    snprintf(url, HEADER, "%s/", req.cwd);
    if(!strlen(url)) return header(59, "bad request");
    char safe[strlen(url) * 3 + 1];
    encode(url, safe);
    return header(30, safe);
  }
  if(!strcspn(req.path, "/")) return ls();

  char *path = strsep(&req.path, "/");
  struct stat sb = {0};
  if(stat(path, &sb) == -1)
    return header(51, "not found");
  if(S_ISREG(sb.st_mode) && sb.st_mode & 0111)
    return cgi(path);
  if(S_ISDIR(sb.st_mode)) {
    size_t current = strlen(req.cwd);
    int bytes = snprintf(req.cwd + current, PATH_MAX - current, "/%s", path);
    if(bytes >= (int)(PATH_MAX - current))
      return header(50, "path too long");
    if(chdir(path)) return header(51, "not found");
    return route();
  }
  return S_ISREG(sb.st_mode) ? file(path) : header(51, "not found");
}

int gemini(put out, ask who, void *ctx, char *url, int shared) {
  req.out = out;
  req.ctx = ctx;
  req.ongoing = 0;

  size_t eof = strspn(url, valid);
  if(url[eof]) return header(59, "bad request");

  if(strlen(url) >= HEADER) return header(59, "bad request");
  if(strlen(url) <= 2) return header(59, "bad request");
  if(url[strlen(url) - 2] != '\r' || url[strlen(url) - 1] != '\n')
    return 1;
  url[strcspn(url, "\r\n")] = 0;

  req.time = time(0);
  who(req.ctx, &id);

  if(id.provided) {
    syslog(LOG_INFO, "%s {%s CN:%s}", url, id.hash, id.cn);
  } else {
    syslog(LOG_INFO, "%s", url);
  }

  const char *scheme = strsep(&url, ":");
  if(!url || strncmp(url, "//", 2)) return header(59, "bad request");

  if(!strcmp(scheme, "gemini"))
    url += 2;
  else
    return header(53, "nope");

  const char *domain = strsep(&url, "/");
  const char *rawpath = strsep(&url, "?");
  const char *rawquery = url;

  char *port = 0;
  if(domain && (port = strchr(domain, ':'))) *port++ = '\0';

  if(!shared && chdir(domain)) return header(51, "not found");

  char cwd[HEADER] = "";
  char path[HEADER] = {0};
  char query[HEADER] = {0};

  decode(rawpath, path);
  decode(rawquery, query);
  if(*path && ((*path == '/') || strstr(path, "..") || strstr(path, "//")))
    return header(51, "not found");

  req.cwd = cwd;
  req.path = path;
  req.query = query;
  return route();
}


