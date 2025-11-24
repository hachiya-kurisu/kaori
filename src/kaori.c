// see us after school for copyright and license details

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <tls.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "gemini.h"

const int backlog = 128;

const char *root = "/var/gemini";
const char *user = "www";
const char *group = "www";

const char *addr = "::1";
const char *port = "1965";

const char *crt = "/etc/ssl/gemini.crt";
const char *key = "/etc/ssl/private/gemini.key";

int debug = 0;
int shared = 0;

const char *flags = "[-ds] [-u user] [-g group] [-a address] [-p port] "
                    "[-r root] [-c certificate] [-k private key]";

static void usage(const char *name) {
  fprintf(stderr, "usage: %s %s\n", name, flags);
}

static void out(void *ctx, const char *buf, ssize_t len) {
  struct tls *tls = ctx;
  while(len > 0) {
    ssize_t ret = tls_write(tls, buf, (size_t)len);
    if(ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) continue;
    if(ret == -1) errx(1, "tls_write failed");
    buf += ret; len -= ret;
  }
}

static void attr(const char *subject, const char *name, char *dst) {
  char needle[128] = {0};
  snprintf(needle, 128, "/%s=", name);
  char *found = strstr(subject, needle);
  if(found) {
    found += strlen(needle);
    size_t len = strcspn(found, "/");
    snprintf(dst, 128, "%.*s", (int)len, found);
  }
}

static void who(void *ctx, struct identity *id) {
  struct tls *tls = ctx;
  id->provided = tls_peer_cert_provided(tls);
  if(id->provided) {
    id->hash = (char *)tls_peer_cert_hash(tls);
    id->subject = (char *)tls_peer_cert_subject(tls);
    if(id->subject) {
      attr(id->subject, "CN", id->cn);
      attr(id->subject, "UID", id->uid);
      attr(id->subject, "emailAddress", id->email);
      attr(id->subject, "O", id->org);
    }
  }
}

int main(int argc, char *argv[]) {
  int c;
  while((c = getopt(argc, argv, "dsu:g:a:p:r:c:k:")) != -1) {
    switch(c) {
      case 'd': debug = 1; break;
      case 's': shared = 1; break;
      case 'u': user = optarg; break;
      case 'g': group = optarg; break;
      case 'a': addr = optarg; break;
      case 'p': port = optarg; break;
      case 'r': root = optarg; break;
      case 'c': crt = optarg; break;
      case 'k': key = optarg; break;
      default: usage(argv[0]); exit(1);
    }
  }

  if(!strtonum(port, 1, 65535, 0)) errx(1, "invalid port");

  tzset();

  struct tls_config *tlsconf = 0;
  struct tls *ctx = 0;

  if(!(ctx = tls_server())) errx(1, "tls_server failed");
  if(!(tlsconf = tls_config_new())) errx(1, "tls_config_new failed");
  if(tls_config_set_key_file(tlsconf, key) < 0)
    errx(1, "tls_config_set_key_file failed");
  if(tls_config_set_cert_file(tlsconf, crt) < 0)
    errx(1, "tls_config_set_cert_file failed");

  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_configure(ctx, tlsconf) < 0)
    errx(1, "tls_configure failed");

  struct addrinfo hints, *res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int err = getaddrinfo(addr, port, &hints, &res);
  if(err)
    errx(1, "getaddrinfo: %s", gai_strerror(err));

  int server = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if(server == -1)
    errx(1, "socket failed");

  struct timeval tv = {.tv_sec = 10};

  int opt = 1;
  if(setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1)
    errx(1, "setsockopt TCP_NODELAY failed");
  if(setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    errx(1, "setsockopt SO_REUSEADDR failed");
  if(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
    errx(1, "setsockopt SO_RCVTIMEO failed");
  if(setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1)
    errx(1, "setsockopt SO_SNDTIMEO failed");

  if(bind(server, res->ai_addr, res->ai_addrlen))
    errx(1, "bind failed: %s", strerror(errno));

  freeaddrinfo(res);

  const struct group *grp = {0};
  const struct passwd *pwd = {0};

  if(group && !(grp = getgrnam(group)))
    errx(1, "group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    errx(1, "user %s not found", user);

  if(chdir(root)) errx(1, "chdir failed");

  openlog("kaori", LOG_NDELAY, LOG_DAEMON);

  if(group && setgid(grp->gr_gid)) errx(1, "setgid failed");
  if(user && setuid(pwd->pw_uid)) errx(1, "setuid failed");

#ifdef __OpenBSD__
  if(!debug) daemon(1, 0);
  if(unveil(root, "rwxc")) errx(1, "unveil failed");
  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix flock", 0))
    errx(1, "pledge failed");
#endif

  if(listen(server, backlog)) errx(1, "listen failed");

  signal(SIGCHLD, SIG_IGN);

  struct sockaddr_storage client;
  socklen_t len = sizeof(client);

  int sock;
  while((sock = accept(server, (struct sockaddr *) &client, &len)) > -1) {
    pid_t pid = fork();
    if(pid == -1) errx(1, "fork failed");
    if(!pid) {
      close(server);
      struct tls *tls;
      if(tls_accept_socket(ctx, &tls, sock) < 0)
        errx(1, "tls_accept_socket failed");

      char url[HEADER] = {0};
      if(tls_read(tls, url, HEADER) == -1) {
        tls_close(tls);
        errx(1, "tls_read failed");
      }

      gemini(out, who, tls, url, shared);

      tls_close(tls);
      _exit(0);
    } else {
      close(sock);
    }
  }
  tls_close(ctx);
  tls_free(ctx);
  tls_config_free(tlsconf);
  closelog();
  return 0;
}
