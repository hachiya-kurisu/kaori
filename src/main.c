// see us after school for copyright and license details

#include <pwd.h>
#include <glob.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#include <tls.h>
#include <magic.h>

#include "tsubomi.h"

static void version() {
  printf("%s %s\n", NAME, VERSION);
}

static void usage() {
  printf("%s\t[-hvatpr]\n", NAME);
  printf("\t-h usage\n");
  printf("\t-v version\n");
  printf("\t-a hostname (%s)\n", config.host);
  printf("\t-r root (%s)\n", config.root);
}

#include "../config.h"

int main(int argc, char **argv) {
  int c;
  while((c = getopt(argc, argv, "thvsa:p:r:w")) != -1) {
    switch(c) {
      case 'h': usage(); exit(0);
      case 'v': version(); exit(0);
      case 'a': config.host = optarg; break;
      case 'r': config.root = optarg; break;
    }
  }

  init();

  struct sockaddr_in6 addr;
  int server = socket(AF_INET6, SOCK_STREAM, 0);

  struct tls_config *tlsconf = 0;
  struct tls *tls = 0;
  struct tls *tls2 = 0;

  int opt = 1;
  int b;

	char *ciphers = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384";

  if(tls_init() < 0) exit(1);
  tlsconf = tls_config_new();
  if(!tlsconf) exit(1);

  tls = tls_server();
  if(!tlsconf) exit(1);

  unsigned int protocols = 0;
  if(tls_config_parse_protocols(&protocols, "secure") < 0) exit(1);
  tls_config_set_protocols(tlsconf, protocols);

  tls_config_verify_client_optional(tlsconf);
  tls_config_insecure_noverifycert(tlsconf);

  if(tls_config_set_ciphers(tlsconf, ciphers) < 0) exit(1);

  if(tls_config_set_key_file(tlsconf, "/etc/ssl/private/blekksprut.net.key") < 0) exit(1);
  if(tls_config_set_cert_file(tlsconf, "/etc/ssl/blekksprut.net.crt") < 0) exit(1);

  if(tls_configure(tls, tlsconf) < 0) exit(1);

  bzero(&addr, sizeof(addr));

  // if(chroot(config.root)) return 1;
  if(pledge("stdio inet proc dns exec rpath wpath cpath getpw unix", 0))
    return 1;
  daemon(0, 0);
  if(chdir(config.root)) return 1;

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(1965);
  addr.sin6_addr = in6addr_any;

  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, 4);

  b = bind(server, (struct sockaddr *) &addr, (socklen_t) sizeof(addr));
  if(b < 0) exit(1);

  listen(server, 10);

  int client;
  socklen_t socklen = sizeof(addr);
  while((client = accept(server, (struct sockaddr *) &addr, &socklen)) > -1) {
    pid_t pid = fork();
    if(!pid) {
      if(tls_accept_socket(tls, &tls2, client) < 0) exit(1);

      char raw[1026] = { 0 };
      int n = tls_read(tls2, raw, 1026);
      if(n == -1) printf("%s\n", tls_error(tls2));

      int provided = tls_peer_cert_provided(tls2);
      if(provided == 1) {
        setenv("TSUBOMI_CLIENT", tls_peer_cert_hash(tls2), 1);
      }

      char ip[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN);

      setenv("TSUBOMI_PEERADDR", ip, 1);

      config.tls = tls2;
      tsubomi(raw);

      close(server);
    }
    close(client);
  }

  tls_close(tls);
  tls_free(tls);
  tls_config_free(tlsconf);

  return 0;
}

