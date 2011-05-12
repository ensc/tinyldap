#include <stdio.h>
#include <byte.h>
#include <stdlib.h>
#include "asn1.h"

#include "printasn1.c"

unsigned long oid[]={1,2,840,113549,1};
const unsigned long oidlen = sizeof(oid) / sizeof(oid[0]);

main() {
  char buf[1024];
  int l,i;
  struct oid o;
  struct string B;
  B.s="\xfe\x74";
  B.l=8+6;
  o.l=oidlen;
  o.a=oid;
  byte_zero(buf,1024);
  l=fmt_asn1generic(buf,"*{isbo}",8,23,"fnord",&B,&o);
  printf("formatted into %d bytes\n",l);
  {
    printf("-> ");
    for (i=0; i<l; ++i)
      printf("%02x ",(unsigned char)(buf[i]));
    printf("\n");
  }

  printasn1(buf,buf+l);


  {
    unsigned long a;
    unsigned long a2;
    unsigned long b;
    struct string c;
    struct string d;
    struct string e;
    l=scan_asn1generic(buf,buf+l,"*{!isbo}",&a,&a2,&b,&c,&e,&d);
    printf("%lu\n",l);
    if (l) {
      printf("got application tag %d (should be 8)\n",a);
      printf("got sequence length %d\n",a2);
      printf("got integer %d (should be 23)\n",b);
      printf("got string \"%.*s\" (should be \"fnord\")\n",c.l,c.s);

      printf("got bitstring length %d: ",e.l);
      for (i=0; i*8<e.l; ++i)
	printf("%02x",(unsigned char)e.s[i]);
      printf("\n");

      printf("got oid ");
      {
	struct oid o;
	size_t mlen=scan_asn1rawoid(d.s,d.s+d.l,NULL,&o.l);
	if (mlen==0 && o.l==0) {
	  puts("oid parse error!");
	  return 0;
	}
	o.a=malloc(o.l*sizeof(o.a[0]));
	if (!o.a) {
	  puts("memory allocation error!");
	  return 0;
	}
	mlen=scan_asn1rawoid(d.s,d.s+d.l,o.a,&o.l);
	for (i=0; i<o.l; ++i)
	  printf("%d%s",o.a[i],i+1<o.l?".":" (should be 1.2.840.113549.1)\n");
      }
    }
  }
}
