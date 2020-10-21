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
  setbuf(stdout, 0);
  if(chdir(config.root)) return 1;
  char raw[1026] = { 0 };
  if(!fgets(raw, 1026, stdin)) return 1;

  setenv("TSUBOMI_PEERADDR", "-", 1);
  return tsubomi(raw);
}

