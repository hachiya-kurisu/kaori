#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>

struct mime {
  char *ext;
  char *type;
};

static const struct mime types[] = {
  {".gmi", "text/gemini"},
  {".txt", "text/plain"},
  {".jpg", "image/jpeg"},
  {".jpeg", "image/jpeg"},
  {".png", "image/png"},
  {".gif", "image/gif"},
  {".jxl", "image/jxl"},
  {".webp", "image/webp"},
  {".mp3", "audio/mpeg"},
  {".m4a", "audio/mp4"},
  {".mp4", "video/mp4"},
  {".wav", "audio/wav"},
  { 0, 0 },
};

const char *valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789"
                    "-._~:/?#[]@!$&'()*+,;=%\r\n";

int dig(char *path, char *dst, char *needle) {
  FILE *fp = fopen(path, "r");
  if(!fp) return -1;
  char buf[LINE_MAX];
  int retval = 0;
  while(fgets(buf, LINE_MAX, fp)) {
    buf[strcspn(buf, "\r\n")] = 0;
    if(needle && !strcmp(buf, needle)) {
      retval = 1;
      break;
    } else if(dst) {
      strlcpy(dst, buf, LINE_MAX);
      break;
    }
  }
  fclose(fp);
  return retval;
}

char *mime(char *path) {
  static char type[PATH_MAX] = {0};

  char override[PATH_MAX] = {0};
  snprintf(override, PATH_MAX, ".%s.mime", path);
  if(dig(override, type, 0) != -1) return type;

  char *ext = strchr(path, '.');
  if(!ext)
    return fallback;

  for (int i = 0; types[i].ext != 0; i++) {
    if(!strcasecmp(ext, types[i].ext)) {
      return types[i].type;
    }
  }
  return fallback;
}

void attr(const char *subject, char *key, char *dst) {
  char needle[128] = {0};
  snprintf(needle, 128, "/%s=", key);
  char *found = strstr(subject, needle);
  if(found) {
    found += strlen(needle);
    size_t len = strcspn(found, "/");
    snprintf(dst, 128, "%.*s", (int)len, found);
  }
}

void encode(char *src, char *dst) {
  unsigned char *s = (unsigned char *) src;
  if(!strlen((char *) s)) {
    dst[0] = '\0';
    return;
  }
  static char skip[256] = {0};
  if(!skip[(int) '-']) {
    unsigned int i;
    for(i = 0; i < 256; i++)
      skip[i] = strchr(valid, i) ? i : 0;
  }
  for(; *s; s++) {
    if(skip[(int) *s]) snprintf(dst, 2, "%c", skip[(int) *s]), ++dst;
    else {
      int bytes = snprintf(dst, 4, "%%%02x", *s);
      if(bytes <= 0) {
        *dst = '\0';
        return;
      }
      dst += bytes;
    }
  }
  *dst = '\0';
}

int decode(char *src, char *dst) {
  int pos = 0;
  char buf[3] = {0};
  unsigned int decoded;
  while(src && *src) {
    buf[pos] = *src;
    if(pos == 2) {
      if(buf[0] == '%' && isxdigit(buf[1]) && isxdigit(buf[2])) {
        sscanf(buf, "%%%2x", &decoded);
        *dst++ = decoded;
        memset(buf, 0, 3);
        pos = 0;
      } else {
        *dst++ = buf[0];
        memmove(buf, &buf[1], 2);
        buf[2] = 0;
      }
    } else {
      pos++;
    }
    src++;
  }
  char *rest = buf;
  while(pos--) *dst++ = *rest++;
  *dst++ = '\0';
  return 0;
}
