// see us after school for copyright and license details

#define _PR_HAVE_LARGE_OFF_T

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <glob.h>
#include <err.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <magic.h>
#include <tls.h>

#include "tsubomi.h"

char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              "abcdefghijklmnopqrstuvwxyz0123456789"
              "-._~:/?#[]@!$&'()*+,;=%\r\n";

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
  if(strstr(mime, "text/") == mime) return textmime;
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

void gmilink(char *buf) {
  char *p = buf;
  strsep(&p, " \t");
  char *link = strsep(&p, " \t\r\n");
  char *text = p ? strsep(&p, "\r\n") : "";
  char encoded[strlen(link) * 3 + 1];
  encode(link, encoded);
  char line[BUFSIZ];
  if(text) {
    snprintf(line, BUFSIZ, "=> %s %s\n", encoded, text);
  } else {
    snprintf(line, BUFSIZ, "=> %s\n", encoded);
  }
  writebuf(line, strlen(line));
}

void gmitransfer(int fd) {
  FILE *fp = fdopen(fd, "r");
  char buf[BUFSIZ];
  while(fgets(buf, BUFSIZ, fp)) {
    if(strstr(buf, "=>") == buf) gmilink(buf);
    else writebuf(buf, strlen(buf));
  }
  fclose(fp);
}

void transfer(int fd) {
  char buf[BUFSIZ] = { 0 };
  ssize_t len;
  while((len = read(fd, buf, BUFSIZ)) != 0) {
    if(len > 0) {
      writebuf(buf, len);
    }
  }
}

void footer() {
  int fd = open(".footer.gmi", O_RDONLY);
  if(fd == -1) return;
  transfer(fd);
  close(fd);
}

int servefile(char *path) {
  int fd = open(path, O_RDONLY);
  if(fd == -1) return header(51, "not found");

  char *mime = classify(path);

  int isgemini = strstr(mime, "text/gemini") == mime;

  header(20, mime);

  isgemini ? gmitransfer(fd) : transfer(fd);

  close(fd);

  if(strstr(mime, "text/gemini") == mime) footer();

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

int list(char *current) {
  struct stat ifs = { 0 };
  stat(indx, &ifs);

  if(S_ISREG(ifs.st_mode))
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
    asprintf(&full, "%s/%s", current, path);
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

  char buf[BUFSIZ] = { 0 };
  ssize_t len;
  while((len = read(fd[0], buf, BUFSIZ)) != 0) {
    writebuf(buf, len);
  }
  wait(0);
  return 0;
}

int authorized() {
  FILE *f = fopen(".authorized", "r");
  if(!f) return 1;

  char *peer = getenv("TSUBOMI_CLIENT");
  if(!peer) {
    fclose(f);
    return 0;
  }

  char buf[BUFSIZ];

  int ret = 0;
  while(fgets(buf, BUFSIZ, f) != 0) {
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

int serve(char *current, char *remaining, char *query) {
  if(!remaining)  {
    char *url;
    asprintf(&url, "%s/", current);
    if(!strlen(url)) return header(59, "bad request");

    char encoded[strlen(url) * 3 + 1];
    encode(url, encoded);
    return header(30, encoded);
  }

  if(!strcspn(remaining, "/"))
    return list(current);

  char *raw = strsep(&remaining, "/");
  char path[strlen(raw)];
  decode(raw, path);

  struct stat fs = { 0 };
  stat(path, &fs);

  if(S_ISREG(fs.st_mode) && fs.st_mode & S_IXOTH)
    return cgi(path, remaining, query);

  if(S_ISDIR(fs.st_mode)) {
    sprintf(current + strlen(current), "/%s", path);
    if(chdir(path)) return header(51, "not found");
    if(!authorized()) return unauthorized();
    setmime(".mime");
    return serve(current, remaining, query);
  }
  if(S_ISREG(fs.st_mode)) return servefile(path);

  char inferred[LINE_MAX];
  sprintf(inferred, "%s.gmi", path);
  memset(&fs, 0, sizeof(fs)); 
  stat(inferred, &fs);
  if(S_ISREG(fs.st_mode)) return servefile(inferred);

  return header(51, "not found");
}

int tsubomi(char *raw) {
  char url[HEADER] = { 0 };

  size_t eof = strspn(raw, valid);
  if(raw[eof]) return header(59, "bad request");

  if(strlen(raw) >= HEADER) return header(59, "bad request");
  if(strlen(raw) <= 2) return header(59, "bad request");
  if(raw[strlen(raw) - 2] != '\r' || raw[strlen(raw) - 1] != '\n') {
    return 1;
  }
  checkcert();

  char *domain = 0, *port = 0, *path = 0, *query = 0;
  for(int i = (int) strlen(raw); i >= 0; i--)
    if(raw[i] == '\n' || raw[i] == '\r') raw[i] = '\0';

  sprintf(url, "%s", raw);

  domain = url;
  if(strstr(domain, "gemini://") == domain) {
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
    fprintf(fp, "%s:%s", peer, raw);
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
    if(strstr(domain, domains[i]) == domain) {
      ok = 1;
      break;
    }
  }
  if(!ok) return header(53, "refused");

  if(chdir(domain)) return header(59, "refused");

  if(path && *path == '/') return header(51, "not found");
  if(path && strstr(path, "..")) return header(51, "not found");
  if(path && strstr(path, "//")) return header(51, "not found");

  char current[HEADER] = "";

  if(!authorized()) return unauthorized();
  setmime(".mime");

  return serve(current, path, query);
}

