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

#include <magic.h>

#ifndef __OpenBSD__
int pledge(__attribute__((unused)) void *_, ...) {
  return 0;
}
#endif

#include "tsubomi.h"


static void version() {
  printf("%s %s\n", NAME, VERSION);
}

static void usage() {
  printf("%s\t[-hvatpr]\n", NAME);
  printf("\t-h usage\n");
  printf("\t-v version\n");
  printf("\t-a hostname (%s)\n", server.host);
  printf("\t-r root (%s)\n", server.root);
}

#include "../config.h"

int main(int argc, char **argv) {
  int c;
  while((c = getopt(argc, argv, "thvsa:p:r:w")) != -1) {
    switch(c) {
      case 'h': usage(); exit(0);
      case 'v': version(); exit(0);
      case 'a': server.host = optarg; break;
      case 'r': server.root = optarg; break;
    }
  }

  init();
  // if(!chroot(server.root)) {
  //   chdir("/");
  // } else {
  // }
  if(chdir(server.root)) return 1;
  if(pledge("stdio exec rpath wpath cpath getpw", 0)) return 1;

  return tsubomi();
}

