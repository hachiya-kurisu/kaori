// see us after school for copyright and license details

#define _PR_HAVE_LARGE_OFF_T

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <glob.h>
#include <err.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <magic.h>
#include <tls.h>

#include "kaori.h"
#include "../config.h"

char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              "abcdefghijklmnopqrstuvwxyz0123456789"
              "-._~:/?#[]@!$&'()*+,;=%\r\n";

static void version() {
  printf("%s %s\n", NAME, VERSION);
}

static void usage() {
  printf("%s\t[-hvr]\n", NAME);
  printf("\t-h usage\n");
  printf("\t-v version\n");
  printf("\t-r root (%s)\n", root);
}

void setmime(char *path) {
  FILE *f = fopen(path, "r");
  if(!f) return;
  fgets(textmime, 256, f);
  while(textmime[strlen(textmime) - 1] == '\n')
    textmime[strlen(textmime) - 1] = '\0';
  fclose(f);
}

char *classify(char *path) {
  char override[strlen(path) + 7];
  sprintf(override, ".%s.mime", path);
  setmime(override);

  char *mime = (char *) magic_file(cookie, path);
  if(!strncmp(mime, "text/", 5)) return textmime;
  return mime;
}

char *certattr(const char *subject, char *key) {
  char needle[LINE_MAX] = { 0 };
  sprintf(needle, "/%s=", key);

  char *found = strstr(subject, needle);
  if(found) {
    found += strlen(needle);
    char *end = strchr(found, '/');
    char *result;
    asprintf(&result, "%.*s", (int) (end - found), found);
    return result;
  }
  return 0;
}

void checkcert() {
  int provided = tls_peer_cert_provided(client);
  if(!provided) return;

  setenv("TSUBOMI_CERT_PROVIDED", "true", 1);
  setenv("TSUBOMI_CLIENT", tls_peer_cert_hash(client), 1);

  const char *subject = tls_peer_cert_subject(client);
  char *uid = certattr(subject, "UID");
  char *email = certattr(subject, "emailAddress");
  char *organization = certattr(subject, "O");

  if(uid) setenv("TSUBOMI_UID", uid, 1);
  if(email) setenv("TSUBOMI_EMAIL", email, 1);
  if(organization) setenv("TSUBOMI_ORGANIZATION", organization, 1);

  int notbefore = tls_peer_cert_notbefore(client);
  int notafter = tls_peer_cert_notafter(client);

  time_t now = time(0);
  if(notbefore != -1 && difftime(now, notbefore) < 0) {
    setenv("TSUBOMI_CERT_INVALID", "Certificate is not yet valid", 1);
  }
  if(notafter != -1 && difftime(notafter, now) < 0) {
    setenv("TSUBOMI_CERT_INVALID", "Certificate is no longer valid", 1);
  }
}

void encode(char *raw, char *enc) {
  unsigned char *s = (unsigned char *) raw;
  if(!strlen((char *) s)) {
    enc[0] = '\0';
    return;
  }
  static char skip[256] = { 0 };
  if(!skip[(int) '-']) {
    unsigned int i;
    for(i = 0; i < 256; i++)
      skip[i] = strchr(valid, i) ? i : 0;
  }
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

void writebuf(char *buf, int len) {
  while(len > 0) {
    ssize_t ret = tls_write(client, buf, len);
    if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
    if(ret == -1) errx(1, "tls_write: %s", tls_error(client));
    buf += ret;
    len -= ret;
  }
}

int header(int status, char *meta) {
  char buf[HEADER];
  if(strlen(meta) > 1024) return 1;
  int len = snprintf(buf, HEADER, "%d %s\r\n", status, *meta ? meta : "");
  if(len <= 0) return 1;
  writebuf(buf, len);
  return 0;
}

void transfer(int fd) {
  char buf[BUFFER] = { 0 };
  ssize_t len;
  while((len = read(fd, buf, BUFFER)) != 0) {
    if(len > 0) {
      writebuf(buf, len);
    }
  }
}

int servefile(char *path) {
  int fd = open(path, O_RDONLY);
  if(fd == -1) return header(51, "not found");

  char *mime = classify(path);
  header(20, mime);
  transfer(fd);
  close(fd);

  return 0;
}

void entry(char *path, char *name, char *mime, double size) {
  char *buf;
  char encoded[strlen(path) * 3 + 1];
  encode(path, encoded);
  int len = asprintf(&buf, "=> %s %s [%s %.2f KB]\n",
      encoded, name, mime, size);
  if(len > 0) writebuf(buf, len);
}

int list(char *cwd) {
  struct stat sb = { 0 };
  stat(indx, &sb);

  if(S_ISREG(sb.st_mode))
    return servefile(indx);

  header(20, textmime);

  glob_t res;
  if(glob("*", GLOB_MARK, 0, &res)) {
    char *empty = "(*^o^*)\r\n";
    writebuf(empty, strlen(empty));
    return 0;
  }
  for(size_t i = 0; i < res.gl_pathc; i++) {
    char *path = res.gl_pathv[i];
    struct stat fs = { 0 };
    stat(path, &fs);
    double size = fs.st_size / 1000.0;
    char *full;
    asprintf(&full, "%s/%s", cwd, path);
    char *mime = classify(path);
    entry(full, path, mime, size);
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
  if(pid == -1) errx(1, "fork failed");

  if(!pid) {
    dup2(fd[1], 1);
    close(fd[0]);
    char *argv[] = { path, data, query };
    execv(path, argv);
  }
  close(fd[1]);

  char buf[BUFFER] = { 0 };
  ssize_t len;
  while((len = read(fd[0], buf, BUFFER)) != 0) {
    writebuf(buf, len);
  }
  wait(0);
  return 0;
}

int fallback(char *notfound) {
  char path[LINE_MAX];
  sprintf(path, "%s.gmi", notfound);
  struct stat sb = { 0 };
  stat(path, &sb);

  if(S_ISREG(sb.st_mode))
    return servefile(path);

  return header(51, "not found");
}

int authorized() {
  FILE *f = fopen(".authorized", "r");
  if(!f) return 1;

  char *peer = getenv("TSUBOMI_CLIENT");
  if(!peer) {
    fclose(f);
    return 0;
  }

  char buf[BUFFER];

  int ret = 0;
  while(fgets(buf, BUFFER, f) != 0) {
    buf[strcspn(buf, "\n")] = 0;
    if(!strcmp(buf, peer)) {
      ret = 1;
      break;
    };
  }
  return ret;
}

int unauthorized() {
  if(getenv("TSUBOMI_CLIENT")) {
    return header(61, "Certificate not authorized");
  } else {
    return header(60, "Client certificate required"); 
  }
}

int route(char *cwd, char *remaining, char *query) {
  if(!authorized()) return unauthorized();
  setmime(".mime");

  if(!remaining)  {
    char *url;
    asprintf(&url, "%s/", cwd);
    if(!strlen(url)) return header(59, "bad request");

    char encoded[strlen(url) * 3 + 1];
    encode(url, encoded);
    return header(30, encoded);
  }

  if(!strcspn(remaining, "/"))
    return list(cwd);

  char *path = strsep(&remaining, "/");

  struct stat sb = { 0 };
  stat(path, &sb);

  if(S_ISREG(sb.st_mode) && sb.st_mode & S_IXOTH)
    return cgi(path, remaining, query);

  if(S_ISDIR(sb.st_mode)) {
    sprintf(cwd + strlen(cwd), "/%s", path);
    if(chdir(path)) return header(51, "not found");
    return route(cwd, remaining, query);
  }
  if(S_ISREG(sb.st_mode)) return servefile(path);

  return fallback(path);
}

int kaori(char *url) {
  size_t eof = strspn(url, valid);
  if(url[eof]) return header(59, "bad request");

  if(strlen(url) >= HEADER) return header(59, "bad request");
  if(strlen(url) <= 2) return header(59, "bad request");
  if(url[strlen(url) - 2] != '\r' || url[strlen(url) - 1] != '\n') {
    return 1;
  }
  checkcert();

  char *domain = 0, *port = 0, *path = 0, *query = 0;
  for(int i = (int) strlen(url); i >= 0; i--)
    if(url[i] == '\n' || url[i] == '\r') url[i] = '\0';

  domain = url;
  if(!strncmp(domain, "gemini://", 9)) {
    domain += 9;
  } else {
    return header(59, "bad request");
  }

  if(domain && (path = strchr(domain, '/'))) *path++ = '\0';
  if(path && (query = strchr(path, '?'))) *query++ = '\0';
  if(domain && (port = strchr(domain, ':'))) *port++ = '\0';

  if(port && strcmp(port, "1965")) return header(53, "refused");

  char *peer = getenv("TSUBOMI_PEERADDR");
  FILE *fp = fopen(logp, "a");
  if(fp) {
    fprintf(fp, "%s:%s", peer, path);
    if(getenv("TSUBOMI_CERT_PROVIDED")) {
      fprintf(fp, " [%s uid:%s email:%s %s]", getenv("TSUBOMI_CLIENT"),
          getenv("TSUBOMI_UID"), getenv("TSUBOMI_EMAIL"),
          getenv("TSUBOMI_CERT_INVALID") ? "-" : "+");
    }
    fprintf(fp, "\n");
    fclose(fp);
  }

  int ok = 0;
  for(int i = 0; domains[i]; i++) {
    if(!strncmp(domain, domains[i], strlen(domain))) {
      ok = 1;
      break;
    }
  }
  if(!ok) return header(53, "refused");

  if(chdir(domain)) return header(59, "refused");

  char remaining[HEADER] = { 0 };
  decode(path, remaining);

  if(*remaining && *remaining == '/') return header(51, "not found");
  if(*remaining && strstr(remaining, "..")) return header(51, "not found");
  if(*remaining && strstr(remaining, "//")) return header(51, "not found");

  char cwd[HEADER] = "";

  return route(cwd, remaining, query);
}

int main(int argc, char **argv) {
  int c;
  while((c = getopt(argc, argv, "hvr:")) != -1) {
    switch(c) {
      case 'h': usage(); exit(0);
      case 'v': version(); exit(0);
      case 'r': root = optarg; break;
    }
  }

  cookie = magic_open(MAGIC_NONE);
  magic_load(cookie, 0);
  magic_setflags(cookie, MAGIC_MIME_TYPE);

  struct sockaddr_in6 addr;
  int server = socket(AF_INET6, SOCK_STREAM, 0);

  struct tls_config *tlsconf = 0;
  struct tls *tls = 0;
  struct tls *tls2 = 0;

  tls = tls_server();
  if(!tls) errx(1, "tls_server failed");

  tlsconf = tls_config_new();
  if(!tlsconf) errx(1, "tls_config_new failed");

  if(tls_config_set_session_lifetime(tlsconf, 7200) == -1)
    errx(1, "tls_conf_set_session_lifetime failed");
  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_config_set_key_file(tlsconf, keyfile) < 0)
    errx(1, "tls_config_set_key_file failed");
  if(tls_config_set_cert_file(tlsconf, crtfile) < 0)
    errx(1, "tls_config_set_cert_file failed");

  if(tls_configure(tls, tlsconf) < 0)
    errx(1, "tls_configure failed");

  bzero(&addr, sizeof(addr));

  daemon(0, 0);

  struct group *grp = { 0 };
  struct passwd *pwd = { 0 };

  if(group && !(grp = getgrnam(group)))
    errx(1, "getgrnam: group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    errx(1, "getpwnam: user %s not found", user);

  if(secure) {
    if(chroot(root)) errx(1, "chroot failed");
    if(chdir("/")) errx(1, "chdir failed (after chroot)");
  } else {
    if(chdir(root)) errx(1, "chdir failed");
  }

  if(group && grp && setgid(grp->gr_gid)) errx(1, "setgid failed");
  if(user && pwd && setuid(pwd->pw_uid)) errx(1, "setuid failed");

  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix", 0))
    errx(1, "pledge failed");

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(1965);
  addr.sin6_addr = in6addr_any;

  struct timeval timeout;
  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  int opt = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, 4);
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

  if(bind(server, (struct sockaddr *) &addr, (socklen_t) sizeof(addr)))
    errx(1, "bind failed");

  listen(server, 10);

  int sock;
  socklen_t len = sizeof(addr);
  while((sock = accept(server, (struct sockaddr *) &addr, &len)) > -1) {
    pid_t pid = fork();
    if(pid == -1) errx(1, "fork failed");
    if(!pid) {
      close(server);
      if(tls_accept_socket(tls, &tls2, sock) < 0) exit(1);

      char raw[HEADER] = { 0 };

      if(tls_read(tls2, raw, HEADER) == -1)
        errx(1, "tls_read failed");
        
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
      setenv("TSUBOMI_PEERADDR", ip, 1);

      client = tls2;
      kaori(raw);
      tls_close(tls2);
    } else {
      close(sock);
      signal(SIGCHLD, SIG_IGN);
    }
  }

  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);

  return 0;
}

