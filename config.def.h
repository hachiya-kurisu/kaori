char *root = "/var/gemini"; // root path

char *crtfile = "/etc/ssl/gemini.crt"; // certificate
char *keyfile = "/etc/ssl/private/gemini.key"; // key

char *user = "gemini"; // setuid
char *group = "gemini"; // setgid

// domains to serve
struct host hosts[] = {
  { "localhost", "gmidocs" },
  { 0 }
};
