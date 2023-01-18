#include <asn1.h>

static size_t sintpayloadlen(signed long l) {
  size_t i;
  /* For a number like 0x00012345 we want to store only the significant
   * octets, i.e. 0x01 0x23 0x45, so count those here.
   * For >=0 omit the leading 0 octets, for <0 omit leading 0xff.

   * The most significant stores bit double as sign bit, so
   * So: 0x7f => 0x7f but 0x80 => 0x00 0x80.

   * Likewise, -1 => 0xff, -128 => 0x80, -129 => 0xff 0x7f.

   * So we count how often we have to shift until the remainder
   * is 0x7f or less. Put differently: Until (remainder>>7)==0. 
   * Finally we pull the >>7 out of the loop for efficiency. */

  if (l<0) l=~l;	// -128 (0x80) maps to 0x7f, which it becomes after NOT

  l >>= 7;
  for (i=1; l>0; ++i) l >>= 8;
  return i;
}

size_t fmt_asn1sintpayload(char* dest,signed long l) {
  size_t needed=sintpayloadlen(l);
  if (dest) {
    size_t i,n;
    /* need to store big endian */
    /* n is the number of bits to shift right for the next octet */
    for (i=0, n=(needed-1)*8; i<needed; ++i, n-=8)
      dest[i]=(l >> n);
  }
  return needed;
}

#if 0
size_t fmt_asn1sintpayload(char* dest,signed long l) {
  size_t needed=sizeof l,i;
  signed long tmp=0x7f;
  if (l>=0) return fmt_asn1intpayload(dest,l);
  for (i=1; i<needed; ++i) {
    /* assumes two's complement */
    if ((l|tmp) == -1)
      break;
    tmp=(tmp<<8)|0xff;
  }
  if (dest) {
    size_t j=i;
    while (j) {
      --j;
      *dest=(l>>(j*8))&0xff;
      ++dest;
    }
  }
  return i;
}
#endif

#include <asn1.h>

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  assert(sintpayloadlen(0)==1);
  assert(sintpayloadlen(0x7f)==1);
  assert(sintpayloadlen(0x80)==2);
  assert(sintpayloadlen(0x80000000)==5);
  if (sizeof(long)==8) assert(sintpayloadlen(0x8000000000000000ul)==8);
  if (sizeof(long)==8) assert(sintpayloadlen(0x0083456789abcdeful)==8);

  char buf[100];
  buf[1]='!';
  assert(fmt_asn1sintpayload(buf,0)==1 && buf[0]==0 && buf[1]=='!');
  assert(fmt_asn1sintpayload(buf,0x7f)==1 && buf[0]==0x7f && buf[1]=='!');
  buf[2]='!';
  assert(fmt_asn1sintpayload(buf,0x80)==2 && !memcmp(buf,"\x00\x80!",3));
  buf[4]='!';
  assert(fmt_asn1sintpayload(buf,0x7fffffff)==4 && !memcmp(buf,"\x7f\xff\xff\xff!",5));

  assert(fmt_asn1sintpayload(NULL, 0)==1);
  assert(fmt_asn1sintpayload(NULL, 0x7f)==1);
  assert(fmt_asn1sintpayload(NULL, 0x80)==2);
  assert(fmt_asn1sintpayload(NULL, 0x7fffffff)==4);

  // buf[4] is still '!'
  assert(fmt_asn1sintpayload(buf,-2147483648)==4 && !memcmp(buf,"\x80\x00\x00\x00!",5));
  buf[5]='!';
  assert(fmt_asn1sintpayload(buf,0xfffffeff)==5 && !memcmp(buf,"\x00\xff\xff\xfe\xff!",6));
  assert(fmt_asn1sintpayload(NULL, 0xfffffeff)==5);
}
#endif
