typedef struct {
  char *host, *root, *index;
  char *notfound, *back;
  char *log;
} Tsubomi;

extern Tsubomi server;

extern void init(void);
extern int tsubomi(void);

