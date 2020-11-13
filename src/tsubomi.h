typedef struct {
  char *host, *root, *index;
  char *notfound, *back;
  char *log;

  void *tls;
} Tsubomi;

extern Tsubomi config;
extern char *domains[];

extern void init(void);
extern int tsubomi(char *);

