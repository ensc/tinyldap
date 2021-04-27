#include <stdlib.h>
#include <stdio.h>
#include "asn1.h"
#include "libowfat/str.h"
#include "libowfat/textcode.h"
#include "libowfat/fmt.h"
#include "libowfat/byte.h"

struct x509signature {
  struct string oid;	/* you are not expected to actually decode this */
  size_t oididx;	/* if this is (size_t)-1, then the parser did not know the OID.
			   Otherwise it's the index into oid2string.  oid2string[oididx].id
			   should be something like X509_ALG_SHA1RSA (see asn1.h) */
  struct string bitstring;	/* In this string, the length is in bits, not bytes! */
	/* If the length is not a multiple of 8, then the unused bits are missing in the last byte.
	 * The parser already validated that the last byte is padded with 0 bits */
};

struct x509cert {
  enum { v1=0, v1988=0, v2=1, v3=2, v1996=2 } version;
  size_t serial;
  struct x509signature algid;
  struct string issuer;		/* this is the raw asn.1 structure, a SET of "[{op}]" in scan_asn1generic terms */
  time_t notbefore, notafter;
  struct string subject;	/* this is the raw asn.1 structure, a SET of "[{op}]" in scan_asn1generic terms */
  struct x509signature sig;
};

struct rsaprivatekey {
  size_t* modulus,* publicExponent,* privateExponent,* prime1,* prime2,* exponent1,* exponent2,* coefficient;
  struct string otherPrimeInfos;
  size_t* freewhendone;
};

struct dsaprivatekey {
};

void printasn1(const char* buf,const char* max);

static int findindn(struct string* dn,enum x509_oid id,struct string* dest) {
  size_t i;
  const char* c=dn->s;
  const char* max=dn->s+dn->l;
  for (;;) {
    struct string oid;
    size_t l=scan_asn1generic(c,max,"[{op}]",&oid,dest);
    if (l) {
      i=lookupoid(oid.s,oid.l);
      if (i!=(size_t)-1) {	// recognized the oid!
	if (oid2string[i].id==id)
	  return 1;
      }
      c+=l;
    } else break;
  }
  return 0;
}

static size_t base64_decode(const char* cert, size_t l, const char* name, char** dest) {
  /* cert should be something like "-----BEGIN CERTIFICATE-----\n[base64 gunk]\n-----END CERTIFICATE-----\n"
   * l should be strlen(cert), but cert does not need to be 0-terminated
   * name should be something like "CERTIFICATE" or "RSA PRIVATE KEY", what you are trying to decode
   * dest will end up pointing to the decoded data.
   * return value can be 0 if we can't decode the data and it does not
   * look like it's a binary certificate.  Or it can be some length
   * value, in which case dest points to a malloced area of that length
   * with the decoded data in it. */
  size_t taglen=strlen(name)+sizeof("-----BEGIN -----")-1;
  char tag[taglen+1];
  char* c=0,* x;
  tag[fmt_strm(tag,"-----BEGIN ",name,"-----")]=0;
  if (l > 2*taglen && byte_equal(cert,taglen,tag))
certfound:
  {
    size_t cur,used;
    /* "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----" and newlines */
    c=malloc((l-2*taglen)/4*3);
    if (!c) return 0;
    x=c;
    for (cur=taglen; cur+taglen-1<l;) {
      size_t next;
      if (cert[cur]=='\r') ++cur;	/* skip line ending */
      if (cert[cur]=='\n') ++cur;
      next=scan_base64(cert+cur,x,&used);
      if (next==0) break;
      cur+=next;
      x+=used;
    }
    if (!str_start(cert+cur,"-----END ") ||
	byte_diff(cert+cur+sizeof("-----END"),taglen-sizeof("----BEGIN")-1,tag+sizeof("-----BEGIN"))) {
      free(c);
      return 0;
    }
    cert=c;
    l=x-c;
  } else {
    /* Maybe it has text in front of the BEGIN CERTIFICATE line */
    size_t i,a=1;
    for (i=0; i+27+25+2<l; ++i) {
      if (cert[i]!='\n' && cert[i]!='\r' && (cert[i]<' ' || cert[i]>'~')) {
	a=0;
	break;
      }
      if (byte_equal(cert+i,taglen,tag)) {
	cert+=i;
	l-=i;
	goto certfound;
      }
    }
    if (a)	/* if we end up here, it was ascii but did not contain a certificate.  fail. */
      return 0;
  }
  /* if we end up here, we decoded some base64 data or we found some
   * binary data.  See if it looks like x.509 at all.  If it does, it
   * starts with a SEQUENCE_OF, which encodes as '0'. */
  if (*cert!='0') {
parseerror:
    free(c);
    return 0;
  }
  *dest=c;
  return l;
}

size_t scan_rsaprivatekey(const char* cert, size_t l, struct rsaprivatekey* C, char** freewhendone) {
  char* c;
  size_t maxdigits,ret;
  unsigned long version;
  *freewhendone=NULL;
  l=base64_decode(cert,l,"RSA PRIVATE KEY",&c);
  if (!l) return 0;
  if (c!=cert) *freewhendone=c;
  maxdigits=l/sizeof(size_t)+2;
  C->freewhendone=malloc(maxdigits*sizeof(size_t)*8);
  if (!C->freewhendone) {
fail:
    free(*freewhendone);
    freewhendone=NULL;
    return 0;
  }
  C->modulus=C->freewhendone;
  C->publicExponent=C->modulus+maxdigits;
  C->privateExponent=C->publicExponent+maxdigits;
  C->prime1=C->privateExponent+maxdigits;
  C->prime2=C->prime1+maxdigits;
  C->exponent1=C->prime2+maxdigits;
  C->exponent2=C->exponent1+maxdigits;
  C->coefficient=C->exponent2+maxdigits;
  C->otherPrimeInfos.l=0;
  C->otherPrimeInfos.s=NULL;
  if ((ret=scan_asn1generic(c,c+l,"{iIIIIIIII!}",&version,
		       C->modulus,C->publicExponent,C->privateExponent,
		       C->prime1,C->prime2,C->exponent1,C->exponent2,
		       C->coefficient,&C->otherPrimeInfos))) {
    if (version!=0 && version!=1) goto fail;
    if (version==0 && C->otherPrimeInfos.l) goto fail;
    if (version==1 && !C->otherPrimeInfos.l) goto fail;
    if (version==0) C->otherPrimeInfos.s=NULL;
    return ret;
  } else
    goto fail;
}

size_t scan_certificate(const char* cert, size_t l, struct x509cert* C, char** freewhendone) {
  char* c=0,* x;
  *freewhendone=NULL;
  l=base64_decode(cert,l,"CERTIFICATE",&c);
  if (!l) return 0;
  if (c!=cert) *freewhendone=c;
  cert=c;

  /* now for the heavy lifting */
  {
    unsigned long tagforversion;	// must be 0
    unsigned long version;
    struct string oidalg,algparams,pubkeyalg,extensions,oidsig,sigrest,sigdata;
    size_t n,i;
    if ((n=scan_asn1generic(cert,cert+l,"{{ci]i{o!}{!}{uu}{!}{!}!}{o!}b}",
			 &tagforversion,
			 &version,
			 &C->serial,
			 &oidalg, &algparams,
			 &C->issuer,
			 &C->notbefore, &C->notafter,
			 &C->subject,
			 &pubkeyalg,
			 &extensions,
			 &oidsig, &sigrest, &sigdata))) {

      if (version==0)
	printf("X.509 certificate\n");
      else if (version==1)
	printf("X.509v2 certificate\n");
      else if (version==2)
	printf("X.509v3 certificate\n");
      else
	printf("unsupported version %ld (must be 0, 1 or 2)\n",version);

      printf("serial number %lu\n",C->serial);

      printf("issuer: ");
      {
	struct string s;
	if (findindn(&C->issuer,X509_ATTR_COUNTRY,&s))
	  printf("C=%.*s ",(int)s.l,s.s);
	if (findindn(&C->issuer,X509_ATTR_ORG,&s))
	  printf("O=%.*s ",(int)s.l,s.s);
	if (findindn(&C->issuer,X509_ATTR_COMMONNAME,&s))
	  printf("CN=%.*s ",(int)s.l,s.s);
      }
      printf("\n");

      {
	char a[100],b[100];
	a[fmt_httpdate(a,C->notbefore)]=0;
	b[fmt_httpdate(b,C->notafter)]=0;
	printf("valid not before %s and not after %s\n",a,b);
      }

      printf("subject: ");
      {
	struct string s;
	if (findindn(&C->issuer,X509_ATTR_COUNTRY,&s))
	  printf("C=%.*s ",(int)s.l,s.s);
	if (findindn(&C->issuer,X509_ATTR_ORG,&s))
	  printf("O=%.*s ",(int)s.l,s.s);
	if (findindn(&C->issuer,X509_ATTR_COMMONNAME,&s))
	  printf("CN=%.*s ",(int)s.l,s.s);
      }
      printf("\n");

      i=lookupoid(oidalg.s,oidalg.l);
      if (i!=(size_t)-1)
	printf("signature algorithm %s\n",oid2string[i].name);
      else {
	unsigned long temp[100];
	size_t len=100;
	if (scan_asn1rawoid(oidalg.s,oidalg.s+oidalg.l,temp,&len)) {
	  printf("Unknown signature algorithm (oid ");
	  for (i=0; i<len; ++i)
	    printf("%lu%s",temp[i],i+1<len?".":")\n");
	} else
	  printf("I don't know the algorithm and I can't parse/print the OID\n");
      }

      /* pubkeyalg is a SubjectPublicKeyInfo:
	 SubjectPublicKeyInfo ::=        SEQUENCE{
		 algorithm               AlgorithmIdentifier,
		 subjectPublicKey        BIT STRING}

	 AlgorithmIdentifier ::= SEQUENCE{
		 algorithm       OBJECT IDENTIFIER,
		 parameters      ANY DEFINED BY algorithm OPTIONAL}
       */

      {
	struct string pubkeyoid, pubkeyparams, bits;
	if (scan_asn1generic(pubkeyalg.s,pubkeyalg.s+pubkeyalg.l,"{o!}b",&pubkeyoid,&pubkeyparams,&bits)) {

	  i=lookupoid(pubkeyoid.s,pubkeyoid.l);
	  if (i!=(size_t)-1) {
	    printf("public key algorithm %s\n",oid2string[i].name);
	    if (oid2string[i].id==X509_ALG_RSA) {
	      size_t* modulus,* publicExponent;
	      size_t allocsize=bits.l/8+2*sizeof(modulus[0]);
	      modulus=malloc(allocsize);
	      publicExponent=malloc(allocsize);
	      if (!modulus || !publicExponent)
		printf("malloc for RSA bignums failed!\n");
	      else {
		if (scan_asn1generic(bits.s,bits.s+bits.l/8,"{II}",modulus,publicExponent)) {
		  if (publicExponent[0]==1)
		    printf("public exponent %lu\n",publicExponent[1]);
		  else
		    printf("public exponent is larger than a word?!\n");
		  printf("modulus:\n  ");
		  for (i=1; i<=modulus[0]; ++i) {
		    size_t j,k;
		    for (j=0, k=modulus[i]; j<sizeof(modulus[0]); ++j) {
		      printf("%02lx%s",(k>>((sizeof(modulus[0])*8)-(j+1)*8))&0xff,i==modulus[0] && j==sizeof(modulus[0])-1?"":":");
		    }
		    if ((i-1)%4==3)
		      if (i==modulus[0])
			printf("\n");
		      else
			printf("\n  ");
		  }
		} else
		  printf("bignum scanning failed!\n");
	      }
	      free(modulus); free(publicExponent);
	    }
	  } else {
	    unsigned long temp[100];
	    size_t len=100;
	    if (scan_asn1rawoid(pubkeyoid.s,pubkeyoid.s+pubkeyoid.l,temp,&len)) {
	      printf("Unknown public key algorithm (oid ");
	      for (i=0; i<len; ++i)
		printf("%lu%s",temp[i],i+1<len?".":")\n");
	    } else
	      printf("I don't know the public key algorithm and I can't parse/print the OID\n");
	  }

	} else
	  printf("could not parse public key part!\n");

	// parse x.509v3 extensions
	if (version!=2 && extensions.l) {
	  printf("Not X.509v3 but extensions present!?\n");
	} else if (extensions.l) {
	  const char* c=extensions.s;
	  const char* max=extensions.s+extensions.l;
	  struct string extoid,extval;
	  unsigned long noextensions;
	  if (c!=max) {
	    size_t n=scan_asn1generic(c,max,"c{!}}!",&noextensions,&extensions,&extval);
	    if (n==0 || extval.l>0) {
	      printf("failed to parse X.509v3 extensions!\n");
	      c=max;
	    } else {
	      c=extensions.s;
	      max=extensions.s+extensions.l;
	    }
	  }
	  while (c<max) {
	    size_t n=scan_asn1generic(c,max,"{os}",&extoid,&extval);
	    if (n) {
	      size_t i=lookupoid(extoid.s,extoid.l);
	      if (i!=(size_t)-1) {
		printf("X.509 extension %s\n",oid2string[i].name);
	      } else {
		unsigned long temp[100];
		size_t len=100;
		if (scan_asn1rawoid(extoid.s,extoid.s+extoid.l,temp,&len)) {
		  printf("Unknown X.509v3 extension (oid ");
		  for (i=0; i<len; ++i)
		    printf("%lu%s",temp[i],i+1<len?".":")\n");
		} else
		  printf("Failed to parse X.509v3 extension OID\n");
	      }
	      c+=n;
	    } else {
	      printf("X.509v3 extension parse error!\n");
	      printasn1(c,max);
	      break;
	    }
	  }
	}
	/*
			 &extensions,
			 &oidsig, &sigrest, &sigdata))) {
	 */
      }

      return n;

    } else {
      printasn1(cert,cert+l);
      return 0;
    }
  }

}

#include "libowfat/mmap.h"
#include <stdio.h>

#include "printasn1.c"

int main(int argc,char* argv[]) {
  char* freewhendone;
  const char* buf;
  size_t l,n;
  struct x509cert c;
  struct rsaprivatekey k;

  buf=mmap_read(argc>1?argv[1]:"test.pem",&l);
  if (!buf) { puts("test.pem not found"); return 1; }

  n=scan_certificate(buf,l,&c,&freewhendone);
  if (!n)
    printf("failed to parse certificate\n");
  free(freewhendone);

  buf=mmap_read(argc>2?argv[2]:"privatekey.pem",&l);
  if (!buf) { puts("privatekey.pem not found"); return 1; }

  n=scan_rsaprivatekey(buf,l,&k,&freewhendone);
  if (!n)
    printf("failed to parse rsa private key\n");
  free(freewhendone);
  free(k.freewhendone);
}
