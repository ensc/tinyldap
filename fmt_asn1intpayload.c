#include <asn1.h>

static size_t intpayloadlen(unsigned long l) {
  size_t i;
  /* We don't need to store the leading zero octets.
   * So count the non-zero ones.
   * We always need at least 1 octet, even if l comes in as 0.

   * However the most significant encoded bit doubles as sign bit.
   * If it is 1, the decoder will think it is a negative number.
   * We can store 0x7f as 0x7f but need to store 0x80 as 0x0080.

   * So we count how often we have to shift until the remainder
   * is 0x7f or less. Put differently: Until (remainder>>7)==0. 
   * Finally we pull the >>7 out of the loop for efficiency. */
  l >>= 7;
  for (i=1; l>0; ++i) l >>= 8;
  return i;
}

size_t fmt_asn1intpayload(char* dest,unsigned long l) {
  size_t needed=intpayloadlen(l);
  if (dest) {
    size_t i,n;
    /* need to store big endian */
    /* n is the number of bits to shift right for the next octet */
    for (i=0, n=(needed-1)*8; i<needed; ++i, n-=8)
      // shifting by more bits than are in the type is undefined behavior :(
      dest[i]= (n == sizeof(l)*8) ? 0 : (l >> n);
  }
  return needed;
}

#ifdef UNITTEST
#include <assert.h>
#include <string.h>

int main() {
  assert(intpayloadlen(0)==1);
  assert(intpayloadlen(0x7f)==1);
  assert(intpayloadlen(0x80)==2);
  assert(intpayloadlen(0x80000000)==5);
  if (sizeof(long)==8) assert(intpayloadlen(0x8000000000000000ul)==9);

  char buf[100];
  buf[1]='!';
  assert(fmt_asn1intpayload(buf,0)==1 && buf[0]==0 && buf[1]=='!');
  assert(fmt_asn1intpayload(buf,0x7f)==1 && buf[0]==0x7f && buf[1]=='!');
  buf[2]='!';
  assert(fmt_asn1intpayload(buf,0x80)==2 && !memcmp(buf,"\x00\x80!",3));
  buf[4]='!';
  assert(fmt_asn1intpayload(buf,0x7fffffff)==4 && !memcmp(buf,"\x7f\xff\xff\xff!",5));
  buf[5]='!';
  assert(fmt_asn1intpayload(buf,0xfffffeff)==5 && !memcmp(buf,"\x00\xff\xff\xfe\xff!",6));

  assert(fmt_asn1intpayload(NULL, 0)==1);
  assert(fmt_asn1intpayload(NULL, 0x7f)==1);
  assert(fmt_asn1intpayload(NULL, 0x80)==2);
  assert(fmt_asn1intpayload(NULL, 0x7fffffff)==4);
  assert(fmt_asn1intpayload(NULL, 0xffffffff)==5);
}
#endif
