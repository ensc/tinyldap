#include <stdio.h>
#include <libowfat/byte.h>
#include <stdlib.h>
#include "asn1.h"
#include <libowfat/mmap.h>
#include <ctype.h>

#include "printasn1.c"

int main(int argc,char* argv[]) {
  const char* buf;
  size_t l;

  if (argc<2) {
    puts("usage: asn1dump filename");
    return 0;
  }
  buf=mmap_read(argv[1],&l);
  if (buf) {
    printasn1(buf,buf+l);
    return 0;
  }
  return 1;
}
