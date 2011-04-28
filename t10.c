#include <stdio.h>
#include <byte.h>
#include "asn1.h"

void printasn1(const char* buf,const char* max) {
  const char* maxstack[100];
  size_t sptr=0;
  size_t indent=0;
  unsigned long tag;
  enum asn1_tagclass tc;
  enum asn1_tagtype tt;
  size_t cl,len;
  maxstack[sptr]=max;
  while (buf<max) {
    size_t i;
    printf("%*s",indent,"");
    cl=scan_asn1tag(buf,maxstack[sptr],&tc,&tt,&tag);
    if (cl==0) {
      printf("[could not parse tag]\n");
      return;
    }
    printf("tag ");
    switch (tc) {
    case UNIVERSAL: printf("UNIVERSAL"); break;
    case APPLICATION: printf("APPLICATION"); break;
    case PRIVATE: printf("PRIVATE"); break;
    case CONTEXT_SPECIFIC: printf("CONTEXT_SPECIFIC"); break;
    default: printf("[illegal tag class 0x%x]\n",tc); return;
    }
    printf(" ");
    switch (tt) {
    case PRIMITIVE: printf("PRIMITIVE"); break;
    case CONSTRUCTED: printf("CONSTRUCTED"); break;
    default: printf("[illegal tag type 0x%x]\n",tt); return;
    }
    printf(" ");
    if (tc!=UNIVERSAL)
      printf("%d (0x%x)",tag,tag);
    else switch (tag) {
    case BOOLEAN: printf("BOOLEAN"); break;
    case INTEGER: printf("INTEGER"); break;
    case BIT_STRING: printf("BIT_STRING"); break;
    case OCTET_STRING: printf("OCTET_STRING"); break;
    case ENUMERATED: printf("ENUMERATED"); break;
    case SEQUENCE_OF: printf("SEQUENCE_OF"); break;
    case SET_OF: printf("SET_OF"); break;
    case UTCTIME: printf("UTCTime"); break;
    default: printf("[unsupported tag 0x%x]",tag); break;
    }

    buf+=cl;
    cl=scan_asn1length(buf,maxstack[sptr],&len);
    if (cl==0) {
      puts("[could not parse length]");
      return;
    }
    printf(" length %zu\n",len);
    buf+=cl;

    if (tc==UNIVERSAL && tt==PRIMITIVE) {
      if (tag==INTEGER) {
	unsigned long l;
	size_t mlen;
	mlen=scan_asn1rawint(buf,maxstack[sptr],cl,&l);
	if (mlen)
	  printf("%*s-> %ld\n",indent,"",l);
      } else if (tag==OCTET_STRING) {
	printf("%*s-> \"",indent,"");
	for (i=0; i<len; ++i) {
	  if (buf[i]<' ')
	    printf("\\x%02x",buf[i]);
	  else
	    putchar(buf[i]);
	}
	printf("\"\n");
      }
    }

    if (tt==CONSTRUCTED) {
      printf("%*s{\n",indent,"");
      indent+=2;
      if (sptr>=99) {
	printf("too many nested constructed elements!\n");
	return;
      }
      maxstack[++sptr]=buf+len;
    } else
      buf+=len;

    while (sptr && maxstack[sptr]<=buf) {
      --sptr;
      indent-=2;
      printf("%*s}\n",indent,"");
    }

  }
}

main() {
  char buf[1024];
  int l,i;
  byte_zero(buf,1024);
  l=fmt_asn1generic(buf,"a{is}",8,23,"fnord");
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
    l=scan_asn1generic(buf,buf+l,"a{!is}",&a,&a2,&b,&c);
    printf("%lu\n",l);
    if (l) {
      printf("got application tag %d (should be 8)\n",a);
      printf("got sequence length %d\n",a2);
      printf("got integer %d (should be 23)\n",b);
      printf("got string \"%.*s\" (should be \"fnord\")\n",c.l,c.s);
    }
  }
}
