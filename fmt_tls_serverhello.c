#include <libowfat/uint16.h>
#include <libowfat/uint32.h>
#include "tinytls.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*

This function parses a client helo and writes the server helo into a
buffer.  It returns the number of bytes in the server helo message,
so you can send it over the TCP connection.  If you pass in NULL as
the destination buffer, the function tells you how much space it
would have needed.  So the regular way to use it is to call it twice.

For efficiency: server helo is around 50 bytes of boilerplate plus
the session data (which comes from the SSL context you are passing
in, field session.l, and its length is limited to 255 bytes).

The function returns (size_t)-1 if the input buffer does not contain a
full client helo message (i.e. "read more data, then try again") and
it returns (size_t)-2 if the input buffer contained an invalid message
("somebody is trying to hack you; drop connection").

If we do not support any of the ciphers or compression methods the other
side wants, this function writes an alert message into the buffer
(length 7).  You are then supposed to send that buffer and close the
connection.

Note that TLS has an encapsulation, so you get an outer message header
and an inner message header.  For both input and output we handle both
headers.

*/

size_t fmt_tls_serverhello(char* dest,const char* clienthello,size_t len,struct ssl_context* sc) {
  size_t l,i;
  int compressionmethod=-1,hostlen=-1;
  const char* host;
  uint16_t best=0,bestprio=0x7fff;

  /* first check if the clienthello is completely there */
  if (len<5 || len<(l=5+uint16_read_big(clienthello+3)))
    return (size_t)-1;

  /* ok, it's complete, now check if it is valid. */
  if (l < 49 ||			// Minimum length with one cipher suite
      clienthello[0]!=22 ||	// Content Type: handshake
      clienthello[1]!=3 ||	// at least SSL 3.0
      clienthello[5]!=1 ||	// Handshake Type: Client Hello
      clienthello[6]!=0 ||	// inner length is 3 bytes, outer length is 2 bytes, so first byte of inner length must be 0
      uint16_read_big(clienthello+7)!=l-9)	// inner length must fit into outer length
invalid:
    return (size_t)-2;

  i=43;
  i+=(unsigned char)clienthello[i]+1;	// session length
  if (i+1>=l) goto invalid;
  {
    uint16 ciphers=uint16_read_big(clienthello+i);
    uint16_t* c;
    size_t j;
    if (ciphers&1) goto invalid;	// must be multiple of two
    if (ciphers==0) goto invalid;	// must support at least one cipher suite
    c=(uint16_t*)(clienthello+i+2);
    if (i+ciphers+2>=l) goto invalid;	// do the ciphers fit in the packet?
    for (j=0; j<ciphers; j+=2) {
      uint16_t cur;
      int p=tls_cipherprio((cur=uint16_read_big((char*)(c+j))));
//      printf("peer supports tls cipher %x\n",cur);
      if (p<0) continue;
      if (p<bestprio) {
	best=cur;
	bestprio=p;
      }
    }
    i+=ciphers+2;			// skip cipher suites
  }
  {
    size_t j,n=(unsigned char)clienthello[i];
    const char* x=clienthello+i+1;
    if (i+1+clienthello[i]+2>l) goto invalid;	// do the compression methods fit in the packet?
    for (j=0; j<n; ++j)
      if (x[i]==0) compressionmethod=0;	// for now only support method 0 (no compression)
  }
  i+=clienthello[i]+1;	// compression methods
  if (i+uint16_read_big(clienthello+i)+2 != l)	// extensions
    goto invalid;
  i+=2;
  while (i<l) {
    if (i+4>l)
      goto invalid;
    if (clienthello[i]==0 && clienthello[i+1]==0) {	/* server_name extension */
      hostlen=uint16_read_big(clienthello+i+2);
      host=clienthello+i+4;
    }
    if ((i+=4+uint16_read_big(clienthello+i+2))>l)
      goto invalid;
  }
  /* The client hello validated OK; we can generate a reply now. */

  /* do we support any of the ciphers and compression methods? */
  if (bestprio==0x7fff || compressionmethod==-1) {	/* nope */
    return dest?
      fmt_tls_alert_pkt(dest,FATAL,HANDSHAKE_FAILURE) :
      7;
  }

  if (!sc->servername) {
    /* We have not yet copied the data out of the client hello.
     * Do so now. */
    memcpy(sc->theirrandom,clienthello+15,sizeof(sc->theirrandom));
    sc->cipher=best;
    sc->compressionmethod=0;
    if (hostlen!=-1) {
      char* sn;
      if ((sn=malloc(hostlen+1))) {
	memcpy(sn,host,hostlen);
	sn[hostlen]=0;
	sc->servername=sn;
      }
    }
    sc->timestamp=time(0);
  }

  if (sc->session.l>0xff) return 0;

  if (dest) {
    char* x;
    fmt_tls_packet(dest,HANDSHAKE,1+3+2+4+28+1+sc->session.l+2+1+2+5);
    dest+=5;
    dest[0]=2;	// type 2 = server hello
    dest[1]=0;
    uint16_pack_big(dest+2,2+4+28+1+sc->session.l+2+1+2+5);
    uint16_pack_big(dest+4,0x0303);	// version: TLS 1.2
    uint32_pack_big(dest+6,sc->timestamp);
    memcpy(dest+10,sc->myrandom,28);
    x=dest+38;
    *x=sc->session.l;
    memcpy(x+1,sc->session.s,sc->session.l);
    x+=sc->session.l+1;
    uint16_pack_big(x,sc->cipher);
    x[2]=sc->compressionmethod;
    x+=3;
    memcpy(x,"\x00\x05\xff\x01\x00\x01\x00",7);		// this is the renegotiation extension
  }
  return 5+1+3+2+4+28+1+sc->session.l+2+1+2+5;
#if 0
  char type = 2;
  char length[3];	// big endian
  char version[2];	// 0x03, 0x03
  uint32_t gmt_unix_time;	// big endian
  char random[28];
  char session_id_length;
  char session_id[session_id_length];
  char cipher_id[2];
  char compression;			// 0 - none, 1 - deflate
  char extensions_length[2];		// \x00\x05
  char renegotiation_extension[5];	// \xff\x01\x00\x01\x00
#endif

}
