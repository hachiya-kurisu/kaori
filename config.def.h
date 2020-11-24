int secure = 1;

char *root = "/var/gemini";
char *indx = "index.gmi";
char *logp = "tsubomi.log";

char *crtfile = "/etc/ssl/gemini.crt";
char *keyfile = "/etc/ssl/private/gemini.key";

char textmime[256] = "text/gemini";

char *user = "gemini";
char *group = "gemini";

char *domains[] = {
  "localhost",
  0
};

char *overrides[][2] = {
  { "robots.txt", "text/plain" },
  { "humans.txt", "text/plain" },
  { 0 }
};

