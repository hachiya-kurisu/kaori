// see us after school for copyright and license details

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>
#include <err.h>
#include <glob.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <tls.h>

#define HEADER 1027
#define BUFFER 65536

#ifndef __OpenBSD__
int pledge(const char *promises, const char *execpromises) {
  (void) promises;
  (void) execpromises;
  return 0;
}

int unveil(const char *path, const char *permissions) {
  (void) path;
  (void) permissions;
  return 0;
}
#endif

struct host {
  char *domain, *root;
};

struct mime {
  char *ext;
  char *type;
};

static const struct mime types[] = {
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

#include "../config.h"

const char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789"
                    "-._~:/?#[]@!$&'()*+,;=%\r\n";

struct request {
  struct tls *tls;
  time_t time;
  char url[HEADER];
  char *cwd, *path, *query;
  int certified, expired, ongoing;
  char *ip, *hash;
  char cn[128], uid[128], email[128], org[128];
};

int cgi(struct request *, char *);
int file(struct request *, char *);

int setdomain(char *domain) {
  struct host *host = hosts;
  while(host->domain) {
    if(!strcmp(domain, host->domain)) {
      return chdir(host->root) ? 0 : 1;
    }
    host++;
  }
  return 0;
}

int dig(char *path, char *dst, char *needle) {
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

char *mime(char *path) {
  static char type[PATH_MAX] = { 0 };

  char override[PATH_MAX] = { 0 };
  snprintf(override, PATH_MAX, ".%s.mime", path);
  if(dig(override, type, 0) != -1) return type;

  char *ext = strchr(path, '.');
  if(!ext)
    return fallback;

  for (int i = 0; types[i].ext != 0; i++) {
    if(!strcasecmp(ext, types[i].ext)) {
      return types[i].type;
    }
  }
  return fallback;
}

void attr(const char *subject, char *key, char *dst) {
  char needle[128] = { 0 };
  snprintf(needle, 128, "/%s=", key);
  char *found = strstr(subject, needle);
  if(found) {
    found += strlen(needle);
    char *end = strchr(found, '/');
    snprintf(dst, 128, "%.*s", (int) (end - found), found);
  }
}

void encode(char *src, char *dst) {
  unsigned char *s = (unsigned char *) src;
  if(!strlen((char *) s)) {
    dst[0] = '\0';
    return;
  }
  static char skip[256] = { 0 };
  if(!skip[(int) '-']) {
    unsigned int i;
    for(i = 0; i < 256; i++)
      skip[i] = strchr(valid, i) ? i : 0;
  }
  for(; *s; s++) {
    if(skip[(int) *s]) snprintf(dst, 2, "%c", skip[(int) *s]), ++dst;
    else {
      snprintf(dst, 3, "%%%02x", *s);
      while (*++dst);
    }
  }
}

int decode(char *src, char *dst) {
  int pos = 0;
  char buf[3] = { 0 };
  unsigned int decoded;
  while(src && *src) {
    buf[pos] = *src;
    if(pos == 2) {
      if(buf[0] == '%' && isxdigit(buf[1]) && isxdigit(buf[2])) {
        sscanf(buf, "%%%2x", &decoded);
        *dst++ = decoded;
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
  char *rest = buf;
  while(pos--) *dst++ = *rest++;
  *dst++ = '\0';
  return 0;
}

void deliver(struct tls *tls, char *buf, int len) {
  while(len > 0) {
    ssize_t ret = tls_write(tls, buf, len);
    if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
    if(ret == -1) errx(1, "tls_write: %s", tls_error(tls));
    buf += ret; len -= ret;
  }
}

int header(struct request *req, int status, char *meta) {
  if(req->ongoing) return 1;
  if(strlen(meta) > 1024) return 1;
  char buf[HEADER];
  int len = snprintf(buf, HEADER, "%d %s\r\n", status, *meta ? meta : "");
  deliver(req->tls, buf, len);
  req->ongoing = 1;
  return 0;
}

void include(struct request *req, char *buf) {
  buf += strspn(buf, " \t");
  buf[strcspn(buf, "\r\n")] = 0;
  struct stat sb = { 0 };
  stat(buf, &sb);
  if(S_ISREG(sb.st_mode) && sb.st_mode & S_IXOTH) {
    cgi(req, buf);
  } else if(S_ISREG(sb.st_mode)) {
    file(req, buf);
  }
}

void transfer(struct request *req, int fd) {
  char buf[BUFFER] = { 0 };
  ssize_t len;
  while((len = read(fd, buf, BUFFER)) != 0)
    deliver(req->tls, buf, len);
}

int file(struct request *req, char *path) {
  int fd = open(path, O_RDONLY);
  if(fd == -1) return header(req, 51, "not found");
  char *type = mime(path);
  header(req, 20, type);
  transfer(req, fd);
  close(fd);
  return 0;
}
void humansize(double bytes, char *buffer, size_t len) {
  const char *units[] = { "B", "KB", "MB", "GB", "TB", "PB", "EB" };
  unsigned int i = 0;
  while (bytes >= 1024.0 && i < (sizeof(units) / sizeof(units[0])) - 1) {
    bytes /= 1024.0;
    i++;
  }
  snprintf(buffer, len, "%.1f %s", bytes, units[i]);
}

void entry(struct request *req, char *path) {
  struct stat sb = { 0 };
  stat(path, &sb);

  char full[PATH_MAX];
  snprintf(full, PATH_MAX, "%s/%s", req->cwd, path);

  char safe[strlen(path) * 3 + 1];
  encode(path, safe);

  char *type;
  if (S_ISDIR(sb.st_mode)) {
    type = "directory";
  } else {
    type = mime(path);
  }

  char size[64];
  humansize(sb.st_size, size, sizeof(size));

  char s[PATH_MAX * 4];
  int len = snprintf(s, sizeof(s), "=> %s %s [%s %s]\n", safe, path, type, size);
  deliver(req->tls, s, len);
}

int ls(struct request *req) {
  struct stat sb = { 0 };
  stat("index.gmi", &sb);
  if(S_ISREG(sb.st_mode))
    return file(req, "index.gmi");
  header(req, 20, "text/gemini");
  glob_t res;
  if(glob("*", GLOB_MARK, 0, &res)) {
    char *empty = "(*^o^*)\r\n";
    deliver(req->tls, empty, strlen(empty));
    return 0;
  }
  for(size_t i = 0; i < res.gl_pathc; i++) {
    entry(req, res.gl_pathv[i]);
  }
  return 0;
}

int cgi(struct request *req, char *path) {
  setenv("GATEWAY_INTERFACE", "CGI/1.1", 1);
  setenv("QUERY_STRING", req->query ? req->query : "", 1);
  setenv("PATH_INFO", req->path ? req->path : "", 1);
  setenv("SCRIPT_NAME", path ? path : "", 1);
  setenv("REMOTE_ADDR", req->ip, 1);
  setenv("REMOTE_HOST", req->ip, 1);
  setenv("SERVER_PORT", "1965", 1);
  setenv("SERVER_SOFTWARE", "槇村香/202012", 1);
  setenv("SERVER_PROTOCOL", "gemini", 1);
  if(req->certified) {
    setenv("AUTH_TYPE", "Certificate", 1);
    setenv("REMOTE_USER", *req->cn ? req->cn : "", 1);
    setenv("TLS_CLIENT_HASH", req->hash, 1);
  }
  int fd[2];
  pipe(fd);

  pid_t pid = fork();
  if(pid == -1) errx(1, "fork failed");

  if(!pid) {
    dup2(fd[1], 1);
    close(fd[0]);
    char *argv[] = { path, 0 };
    execv(path, argv);
  }
  close(fd[1]);

  char buf[BUFFER] = { 0 };
  ssize_t len;
  while((len = read(fd[0], buf, BUFFER)) != 0) {
    deliver(req->tls, buf, len);
  }
  kill(pid, SIGKILL);
  wait(0);
  return 0;
}

int route(struct request *req) {
  if(!dig(".authorized", 0, req->hash))
    return header(req, req->certified ? 61 : 60, "unauthorized");

  dig(".mime", fallback, 0);

  if(!req->path)  {
    char url[HEADER];
    snprintf(url, HEADER, "%s/", req->cwd);
    if(!strlen(url)) return header(req, 59, "bad request");
    char safe[strlen(url) * 3 + 1];
    encode(url, safe);
    return header(req, 30, safe);
  }
  if(!strcspn(req->path, "/")) return ls(req);

  char *path = strsep(&req->path, "/");
  struct stat sb = { 0 };
  stat(path, &sb);
  if(S_ISREG(sb.st_mode) && sb.st_mode & S_IXOTH) 
    return cgi(req, path);
  if(S_ISDIR(sb.st_mode)) {
    snprintf(req->cwd + strlen(req->cwd), PATH_MAX, "/%s", path);
    if(chdir(path)) return header(req, 51, "not found");
    return route(req);
  }
  return S_ISREG(sb.st_mode) ? file(req, path) : header(req, 51, "not found");
}

int kaori(struct request *req, char *url) {
  size_t eof = strspn(url, valid);
  if(url[eof]) return header(req, 59, "bad request");

  if(strlen(url) >= HEADER) return header(req, 59, "bad request");
  if(strlen(url) <= 2) return header(req, 59, "bad request");
  if(url[strlen(url) - 2] != '\r' || url[strlen(url) - 1] != '\n')
    return 1;
  url[strcspn(url, "\r\n")] = 0;

  req->time = time(0);
  if(tls_peer_cert_provided(req->tls)) {
    req->certified = 1;
    req->hash = (char *) tls_peer_cert_hash(req->tls);

    const char *subject = tls_peer_cert_subject(req->tls);
    if(subject) {
      attr(subject, "CN", req->cn);
      attr(subject, "UID", req->uid);
      attr(subject, "emailAddress", req->email);
      attr(subject, "O", req->org);
    }
    int first = tls_peer_cert_notbefore(req->tls);
    int expiry = tls_peer_cert_notafter(req->tls);
    if(first != -1 && difftime(req->time, first) < 0) req->expired = -1;
    if(expiry != -1 && difftime(expiry, req->time) < 0) req->expired = 1;
  }
  if(req->certified) {
    syslog(LOG_INFO, "%s %s {%s CN:%s}", url, req->ip, req->hash, req->uid);
  } else {
    syslog(LOG_INFO, "%s %s", url, req->ip);
  }

  char *scheme = strsep(&url, ":");
  if(!url || strncmp(url, "//", 2)) return header(req, 59, "bad request");

  if(!strcmp(scheme, "gemini"))
    url += 2;
  else
    return header(req, 53, "nope");

  char *domain = strsep(&url, "/");
  char *rawpath = strsep(&url, "?");
  char *rawquery = url;

  char *port = 0;
  if(domain && (port = strchr(domain, ':'))) *port++ = '\0';
  if(port && strcmp(port, "1965")) return header(req, 53, "refused");

  if(!setdomain(domain)) return header(req, 53, "refused");

  char cwd[HEADER] = "";
  char path[HEADER] = { 0 };
  char query[HEADER] = { 0 };

  decode(rawpath, path);
  decode(rawquery, query);
  if(*path && ((*path == '/') || strstr(path, "..") || strstr(path, "//")))
    return header(req, 51, "not found");

  req->cwd = cwd;
  req->path = path;
  req->query = query;
  return route(req);
}

int main(int argc, char *argv[]) {
  int debug = 0;

  int c;
  while((c = getopt(argc, argv, "d")) != -1) {
    switch(c) {
      case 'd': debug = 1;
    }
  }

  tzset();

  struct sockaddr_in6 addr;
  int server = socket(AF_INET6, SOCK_STREAM, 0);

  struct tls_config *tlsconf = 0;
  struct tls *tls = 0;

  if(!(tls = tls_server())) errx(1, "tls_server failed");
  if(!(tlsconf = tls_config_new())) errx(1, "tls_config_new failed");

  if(tls_config_set_key_file(tlsconf, keyfile) < 0)
    errx(1, "tls_config_set_key_file failed");
  if(tls_config_set_cert_file(tlsconf, crtfile) < 0)
    errx(1, "tls_config_set_cert_file failed");

  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_configure(tls, tlsconf) < 0)
    errx(1, "tls_configure failed");

  struct group *grp = { 0 };
  struct passwd *pwd = { 0 };

  if(group && !(grp = getgrnam(group)))
    errx(1, "group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    errx(1, "user %s not found", user);

  if(!debug)
    daemon(0, 0);

  if(unveil(root, "rwxc")) errx(1, "unveil failed");
  if(chdir(root)) errx(1, "chdir failed");

  openlog("kaori", LOG_NDELAY, LOG_DAEMON);

  if(group && grp && setgid(grp->gr_gid)) errx(1, "setgid failed");
  if(user && pwd && setuid(pwd->pw_uid)) errx(1, "setuid failed");

  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix flock", 0))
    errx(1, "pledge failed");

  bzero(&addr, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(1965);
  addr.sin6_addr = in6addr_loopback;

  struct timeval timeout;
  timeout.tv_sec = 10;

  int opt = 1;
  setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if(bind(server, (struct sockaddr *) &addr, (socklen_t) sizeof(addr)))
    errx(1, "bind failed %d", errno);

  listen(server, 32);

  int sock;
  socklen_t len = sizeof(addr);
  while((sock = accept(server, (struct sockaddr *) &addr, &len)) > -1) {
    pid_t pid = fork();
    if(pid == -1) errx(1, "fork failed");
    if(!pid) {
      close(server);
      struct request req = { 0 };
      if(tls_accept_socket(tls, &req.tls, sock) < 0)
        errx(1, "tls_accept_socket failed");
      char url[HEADER] = { 0 };
      if(tls_read(req.tls, url, HEADER) == -1) {
        tls_close(req.tls);
        errx(1, "tls_read failed");
      }
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
      req.ip = ip;
      kaori(&req, url);
      tls_close(req.tls);
    } else {
      close(sock);
      signal(SIGCHLD, SIG_IGN);
    }
  }
  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);
  closelog();
  return 0;
}
