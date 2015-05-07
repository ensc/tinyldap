#include <tinytls.h>

static uint16_t ciphers[] = {
  TLS_RSA_WITH_AES_256_CBC_SHA256,
  TLS_RSA_WITH_AES_256_CBC_SHA,
};

int tls_cipherprio(uint16_t cipher) {
  size_t i;
  for (i=0; i<sizeof(ciphers)/sizeof(ciphers[0]); ++i)
    if (ciphers[i]==cipher) return i;
  return -1;
}
