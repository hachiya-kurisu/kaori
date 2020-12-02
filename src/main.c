// see us after school for copyright and license details

#define _PR_HAVE_LARGE_OFF_T

#include <pwd.h>
#include <grp.h>
#include <glob.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <tls.h>
#include <magic.h>

#include "tsubomi.h"

static void version() {
  printf("%s %s\n", NAME, VERSION);
}

static void usage() {
  printf("%s\t[-hvr]\n", NAME);
  printf("\t-h usage\n");
  printf("\t-v version\n");
  printf("\t-r root (%s)\n", root);
}

#include "../config.h"

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
  if(!tls) errx(1, "tls_server: failed");

  tlsconf = tls_config_new();
  if(!tlsconf) errx(1, "tls_config_new: failed");

  if(tls_config_set_session_lifetime(tlsconf, 7200) == -1)
    errx(1, "tls_conf_set_session_lifetime: failed");
  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_config_set_key_file(tlsconf, keyfile) < 0)
    errx(1, "tls_config_set_key_file: failed");
  if(tls_config_set_cert_file(tlsconf, crtfile) < 0)
    errx(1, "tls_config_set_cert_file: failed");

  if(tls_configure(tls, tlsconf) < 0)
    errx(1, "tls_configure: failed");

  bzero(&addr, sizeof(addr));

  daemon(0, 0);

  struct group *grp = { 0 };
  struct passwd *pwd = { 0 };

  if(group && !(grp = getgrnam(group)))
    errx(1, "getgrnam: group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    errx(1, "getpwnam: user %s not found", user);

  if(secure) {
    if(chroot(root)) errx(1, "chroot: failed");
    if(chdir("/")) errx(1, "chdir: failed (after chroot)");
  } else {
    if(chdir(root)) errx(1, "chdir: failed");
  }

  if(group && grp && setgid(grp->gr_gid)) errx(1, "setgid: failed");
  if(user && pwd && setuid(pwd->pw_uid)) errx(1, "setuid: failed");

  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix", 0))
    errx(1, "pledge: failed");

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
    errx(1, "bind: failed");

  listen(server, 10);

  int sock;
  socklen_t len = sizeof(addr);
  while((sock = accept(server, (struct sockaddr *) &addr, &len)) > -1) {
    pid_t pid = fork();
    if(!pid) {
      close(server);
      if(tls_accept_socket(tls, &tls2, sock) < 0) exit(1);

      char raw[HEADER] = { 0 };

      if(tls_read(tls2, raw, HEADER) == -1)
        errx(1, "tls_read: failed");
        
      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
      setenv("TSUBOMI_PEERADDR", ip, 1);

      client = tls2;
      tsubomi(raw);
      tls_close(tls2);
    } else {
      close(sock);
      signal(SIGCHLD,SIG_IGN);
    }
  }

  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);

  return 0;
}

