// see us after school for copyright and license details

#include <pwd.h>
#include <grp.h>
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
  setbuf(stdout, 0);

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

  char raw[1026] = { 0 };
  if(!fgets(raw, 1026, stdin)) return 1;

  setenv("TSUBOMI_PEERADDR", "-", 1);
  return tsubomi(raw);
}

