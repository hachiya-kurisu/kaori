#include "gemini.c"

static void checkstr(const char *name, const char *expected, const char *actual) {
  if (strcmp(expected, actual) == 0) {
    printf("✓ %s\n", name);
  } else {
    printf("✗ %s: expected '%s', got '%s'\n", name, expected, actual);
  }
}

int main(void) {
  checkstr("mime .gmi", "text/gemini", mime("test.gmi"));
  checkstr("mime .txt", "text/plain", mime("readme.txt"));
  checkstr("mime no ext", "application/octet-stream", mime("README"));

  char encoded[256] = {0};
  encode("hello world", encoded);
  checkstr("encode spaces", "hello%20world", encoded);

  encode("蜂谷", encoded);
  checkstr("encode kanji", "%e8%9c%82%e8%b0%b7", encoded);

  char decoded[256];
  decode("hello%20world", decoded);
  checkstr("decode spaces", "hello world", decoded);

  char result[256] = {0};

  attr("/CN=蜂谷/O=teatime/", "CN", result);
  checkstr("attr CN", "蜂谷", result);

  attr("/CN=蜂谷/O=teatime/", "O", result);
  checkstr("attr O", "teatime", result);

  attr("/CN=蜂谷", "CN", result);
  checkstr("no trailing slash", "蜂谷", result);

  return 0;
}
