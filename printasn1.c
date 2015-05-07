/* needs stdio.h and asn1.h included */

#include <ctype.h>

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
    printf("%*s",(int)indent,"");
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
      printf("%lu (0x%lx)",tag,tag);
    else switch (tag) {
    case 0: printf("EOI"); break;
    case BOOLEAN: printf("BOOLEAN"); break;
    case INTEGER: printf("INTEGER"); break;
    case BIT_STRING: printf("BIT_STRING"); break;
    case OCTET_STRING: printf("OCTET_STRING"); break;
    case _NULL: printf("NULL"); break;
    case OBJECT_IDENTIFIER: printf("OBJECT_IDENTIFIER"); break;
    case ENUMERATED: printf("ENUMERATED"); break;
    case SEQUENCE_OF: printf("SEQUENCE_OF"); break;
    case SET_OF: printf("SET_OF"); break;
    case PrintableString: printf("PrintableString"); break;
    case IA5String: printf("IA5String"); break;
    case UTCTIME: printf("UTCTime"); break;
    default: printf("[unsupported tag 0x%lx]",tag); break;
    }

    buf+=cl;
    cl=scan_asn1length(buf,maxstack[sptr],&len);
    if (cl==0) {
      puts("[could not parse length]");
      return;
    }
    printf(" length %lu\n",(unsigned long)len);
    buf+=cl;

    if (tc==UNIVERSAL && tt==PRIMITIVE) {
      if (tag==INTEGER) {
	long l;
	size_t mlen;
	mlen=scan_asn1rawint(buf,maxstack[sptr],cl,&l);
	if (mlen)
	  printf("%*s-> %ld\n",(int)indent,"",l);
      } else if (tag==OCTET_STRING || tag==PrintableString || tag==IA5String || tag==UTCTIME || tag==BIT_STRING) {
	printf("%*s-> \"",(int)indent,"");
	for (i=0; i<len; ++i) {
	  if (buf[i]<' ' || buf[i]=='"' || buf[i]==0x7f || buf[i]=='\\') {
	    printf("\\x%02x",(unsigned char)(buf[i]));
	    if (i+1<len && isxdigit(buf[i+1]))
	      printf("\"\"");
	  } else
	    putchar(buf[i]);
	}
	printf("\"\n");
      } else if (tag==OBJECT_IDENTIFIER) {
	struct oid o;
	size_t mlen;
	size_t fnord[1000];
	o.l=1000;
	o.a=fnord;
	mlen=scan_asn1rawoid(buf,buf+len,o.a,&o.l);
	if (mlen) {
	  printf("%*s-> ",(int)indent,"");
	  for (i=0; i<o.l; ++i)
	    printf("%lu%s",(unsigned long)o.a[i],i+1==o.l?"\n":".");
	}
	i=lookupoid(buf,len);
	if (i!=(size_t)-1)
	  printf("%*s(%s)\n",(int)indent,"",oid2string[i].name);
	else {
	  printf("%*s(\"",(int)indent,"");
	  for (i=0; i<len; ++i)
	    printf("\\x%02x",(unsigned char)(buf[i]));
	  printf("\")\n");
	}
      }
    }

    if (tt==CONSTRUCTED) {
      printf("%*s{\n",(int)indent,"");
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
      printf("%*s}\n",(int)indent,"");
    }

  }
}


