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

char *classify(char *path) {
  char *mime = (char *) magic_file(cookie, path);
  for(int i = 0; overrides[i][0]; i++) {
    if(!strcmp(path, overrides[i][0])) return overrides[i][1];
  }
  if(!strcmp(mime, "text/plain")) return textmime;
  return mime;
}

char *certattr(const char *subject, char *key) {
  char needle[LINE_MAX] = { 0 };
  sprintf(needle, "/%s=", key);

  char *found = strstr(subject, needle);
  char *end;
  if(found) {
    found += strlen(needle);
    end = strchr(found, '/');
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

void encode(unsigned char *s, char *enc) {
  if(!strlen((char *) s)) {
    enc[0] = '\0';
    return;
  }
  char skip[256] = { 0 };
  unsigned int i;
  for(i = 0; i < 256; i++)
    skip[i] = isalnum(i) ||
      i == '~' || i == '-' || i == '.' || i == '_' || i == '/' ? i : 0;

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
  char buffer[HEADER];
  int l = snprintf(buffer, HEADER, "%d %s\r\n", status, meta ? meta : "");
  tls_write(client, buffer, l);
  return 0;
}

void transfer(int fd) {
  char buffer[BUFSIZ] = { 0 };
  ssize_t l;
  while((l = read(fd, buffer, BUFSIZ)) != 0) {
    if(l > 0) {
      tls_write(client, buffer, l);
    }
  }
  fflush(stdout);
}

void footer() {
  int fd = open(".footer.gmi", O_RDONLY);
  if(fd == -1) return;
  transfer(fd);
  close(fd);
}

void setmime(char *path) {
  char *dotfile;
  if(path) {
    asprintf(&dotfile, ".%s.mime", path);
  } else {
    dotfile = ".mime";
  }
  FILE *f = fopen(dotfile, "r");
  if(!f) return;
  fgets(textmime, 256, f);
  while(textmime[strlen(textmime) - 1] == '\n')
    textmime[strlen(textmime) - 1] = '\0';
  fclose(f);
}

int servefile(char *path) {
  int fd = open(path, O_RDONLY);
  if(fd == -1) return header(51, "not found");

  setmime(path);

  char *mime = classify(path);

  header(20, mime);
  transfer(fd);
  close(fd);

  if(strstr(mime, "text/gemini") == mime) footer();

  return 0;
}

int list(char *current) {
  struct stat fs = { 0 };
  stat(indx, &fs);

  if(S_ISREG(fs.st_mode))
    return servefile(indx);

  header(20, textmime);

  glob_t res;
  if(glob("*", GLOB_MARK, 0, &res)) {
    char *str = "(*^o^*)\r\n";
    int l = strlen(str);
    tls_write(client, str, l);

    return 0;
  }
  char *path;
  for(size_t i = 0; i < res.gl_pathc; i++) {
    path = res.gl_pathv[i];

    struct stat fs = { 0 };
    stat(path, &fs);

    char ecurrent[(strlen(current) * 3 + 1)];
    encode((unsigned char *) current, ecurrent);

    char epath[(strlen(path) * 3 + 1)];
    encode((unsigned char *) path, epath);

    int len = strlen(epath);
    if(epath[len - 1] == '~') continue;
    if(strstr(epath, ".gmi") == &epath[len - 4]) len -= 4;

    char buffer[BUFSIZ * 32] = { 0 };
    double size = fs.st_size / 1000.0;

    char *mime = classify(path);
    int l = snprintf(buffer, BUFSIZ * 32, "=> %s/%.*s %.*s - %s - %.2f KB\n",
        ecurrent, len, epath, len, epath, mime, size);

    tls_write(client, buffer, l);
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

  char buffer[BUFSIZ] = { 0 };
  ssize_t l;
  while((l = read(fd[0], buffer, BUFSIZ)) != 0) {
    if(l > 0) {
      tls_write(client, buffer, l);
    }
  }
  wait(0);
  return 0;
}

int authorized() {
  FILE *f = fopen(".authorized", "r");
  if(!f) return 1;

  char *peer = getenv("TSUBOMI_CLIENT");
  if(!peer) return 0;

  char buffer[BUFSIZ];
  while(fgets(buffer, BUFSIZ, f) != 0) {
    buffer[strcspn(buffer, "\n")] = 0;
    if(!strcmp(buffer, peer)) return 1;
  }
  return 0;
}

int unauthorized() {
  if(getenv("TSUBOMI_CLIENT")) {
    return header(61, "Certificate not authorized");
  } else {
    return header(60, "Client certificate required"); 
  }
}

int serve(char *current, char *remaining, char *query) {
  // clean up
  if(!remaining)  {
    char ecurrent[(strlen(current) * 3 + 1)];
    encode((unsigned char *) current, ecurrent);
    char url[HEADER] = { 0 };
    snprintf(url, HEADER, "%s/", ecurrent);
    return header(30, url);
  }

  if(!strcspn(remaining, "/"))
    return list(current);

  char *p = strsep(&remaining, "/");

  struct stat fs = { 0 };
  stat(p, &fs);

  if(S_ISREG(fs.st_mode) && fs.st_mode & S_IXOTH)
    return cgi(p, remaining, query);

  if(S_ISDIR(fs.st_mode)) {
    sprintf(current + strlen(current), "/%s", p);
    if(chdir(p)) return header(51, "not found");
    setmime(0);
    if(!authorized()) return unauthorized();

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

char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              "abcdefghijklmnopqrstuvwxyz0123456789"
              "-._~:/?#[]@!$&'()*+,;=%\r\n";

int tsubomi(char *raw) {
  char url[HEADER] = { 0 };
  char path[HEADER] = { 0 };
  char query[HEADER] = { 0 };

  size_t eof = strspn(raw, valid);
  if(raw[eof]) return header(59, "bad request");

  if(strlen(raw) >= HEADER) return header(59, "bad request");
  if(strlen(raw) <= 2) return header(59, "bad request");
  if(raw[strlen(raw) - 2] != '\r' || raw[strlen(raw) - 1] != '\n') {
    return 1;
  }
  checkcert();

  char *domain = 0, *port = 0, *rawpath = 0, *rawquery = 0;
  for(int i = (int) strlen(raw); i >= 0; i--)
    if(raw[i] == '\n' || raw[i] == '\r') raw[i] = '\0';

  sprintf(url, "%s", raw);

  domain = url;
  if(strstr(domain, "gemini://") == domain) {
    domain += 9;
  } else {
    return header(59, "bad request");
  }

  if(domain && (rawpath = strchr(domain, '/'))) *rawpath++ = '\0';
  if(rawpath && (rawquery = strchr(rawpath, '?'))) *rawquery++ = '\0';
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

  decode(rawpath, path);
  decode(rawquery, query);

  if(strstr(path, "..")) return header(51, "not found");
  if(strstr(path, "//")) return header(51, "not found");

  char current[2048] = "";

  setmime(0);
  if(!authorized()) return unauthorized();

  return serve(current, path, query);
}

