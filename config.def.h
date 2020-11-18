int secure = 1;

char *root = "/var/gemini";
char *indx = "index.gmi";
char *logp = "tsubomi.log";

char *crtfile = "/etc/ssl/gemini.crt";
char *keyfile = "/etc/ssl/private/gemini.key";

char *user = "gemini";
char *group = "gemini";

char *domains[] = {
  "localhost",
  0
};

