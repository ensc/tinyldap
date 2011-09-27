#include <stdio.h>
#include <byte.h>
#include <stdlib.h>
#include "asn1.h"
#include "mmap.h"

#include "printasn1.c"

int main(int argc,char* argv[]) {
  char* buf;
  size_t l;

  if (argc<2) {
    printf("usage: asn1dump filename\n");
    return 0;
  }
  buf=mmap_read(argv[1],&l);
  if (buf) {
    printasn1(buf,buf+l);
    return 0;
  }
  return 1;
}
