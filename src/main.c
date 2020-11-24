// see us after school for copyright and license details

#define _PR_HAVE_LARGE_OFF_T

#include <pwd.h>
#include <grp.h>
#include <glob.h>
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

  init();

  struct sockaddr_in6 addr;
  int server = socket(AF_INET6, SOCK_STREAM, 0);

  struct tls_config *tlsconf = 0;
  struct tls *tls = 0;
  struct tls *tls2 = 0;

  if(tls_init() < 0) exit(1);

  tls = tls_server();
  if(!tls) exit(1);

  tlsconf = tls_config_new();
  if(!tlsconf) exit(1);

  if(tls_config_set_session_lifetime(tlsconf, 7200) == -1) exit(1);
  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_config_set_key_file(tlsconf, keyfile) < 0) exit(1);
  if(tls_config_set_cert_file(tlsconf, crtfile) < 0) exit(1);

  if(tls_configure(tls, tlsconf) < 0) {
    printf("%s\n", tls_error(tls));
    exit(1);
  }

  bzero(&addr, sizeof(addr));

  daemon(0, 0);

  struct group *grp = { 0 };
  struct passwd *pwd = { 0 };

  if(setgroup) {
    if (!(grp = getgrnam(setgroup))) return 2;
  }
  if(setuser) {
    if (!(pwd = getpwnam(setuser))) return 3;
  }

  if(secure) {
    if(chroot(root)) return 1;
    if(chdir("/")) return 1;
  } else {
    if(chdir(root)) return 1;
  }

  if(setgroup && grp) {
    if(setgid(grp->gr_gid)) return 5;
  }

  if(setuser && pwd) {
    if(setuid(pwd->pw_uid)) return 7;
  }

  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix", 0))
    return 1;

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

  int bound = bind(server, (struct sockaddr *) &addr, (socklen_t) sizeof(addr));
  if(bound < 0) exit(1);

  listen(server, 10);

  int client;
  socklen_t socklen = sizeof(addr);
  while((client = accept(server, (struct sockaddr *) &addr, &socklen)) > -1) {
    pid_t pid = fork();
    if(!pid) {
      close(server);
      if(tls_accept_socket(tls, &tls2, client) < 0) exit(1);

      char raw[1026] = { 0 };
      int n = tls_read(tls2, raw, 1026);
      if(n == -1) printf("%s\n", tls_error(tls2));

      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);
      setenv("TSUBOMI_PEERADDR", ip, 1);

      tlsptr = tls2;
      tsubomi(raw);
    } else {
      close(client);
      signal(SIGCHLD,SIG_IGN);
    }
  }

  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);

  return 0;
}

