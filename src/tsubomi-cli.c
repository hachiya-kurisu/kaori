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
  printf("%s-cli %s\n", NAME, VERSION);
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

  if(group && !(grp = getgrnam(group)))
    return fatal("group %s not found", group);

  if(user && !(pwd = getpwnam(user)))
    return fatal("user %s not found", user);

  if(secure) {
    if(chroot(root)) return fatal("unable to chroot to %s", root);
    if(chdir("/")) return fatal("unable to chdir to %s", "/");
  } else {
    if(chdir(root)) return fatal("unable to chdir to %s", root);
  }
 
  if(group && grp && setgid(grp->gr_gid)) return fatal("setgid failed", 0);
  if(user && pwd && setuid(pwd->pw_uid)) return fatal("setuid failed", 0);

  char raw[HEADER] = { 0 };
  if(!fgets(raw, HEADER, stdin)) return fatal("fgets failed", 0);

  setenv("TSUBOMI_PEERADDR", "-", 1);
  return tsubomi(raw);
}

