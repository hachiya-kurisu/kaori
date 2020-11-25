#define HEADER 1026

void *tlsptr;

extern char *root;
extern char *indx;
extern char *logp;

extern char *domains[];

extern char textmime[256];

extern void init(void);
extern int tsubomi(char *);

extern char *overrides[][2];

int fatal(char *, char *);
