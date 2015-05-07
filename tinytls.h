#ifndef _TINYTLS_H
#define _TINYTLS_H

#include <stdint.h>
#include <sys/types.h>

/* for struct string: */
#include "asn1.h"

typedef enum {
  NONE,
  FAIL,				// protocol failure, refuse all operations

  READ_CLIENTHELLO,		// tls_accept called, trying to read client hello
  WRITE_ALERTFAIL,		// got something bad, write alert and fail
  WRITE_SERVERHELLO,		// got client hello, trying to write server hello

  WRITE_CLIENTHELLO,		// tls_connect called, trying to write client hello
  READ_SERVERHELLO,		// trying to read server hello
  READ_CERT,			// read server hello, trying to read cert
  READ_SERVERHELLODONE,		// read server hello + cert, trying to read server hello done
} tls_state;

enum { MAXCERT=4 };

struct ssl_context {
  tls_state state;
  char myrandom[28];
  char theirrandom[28];
  time_t timestamp;	/* so we can age out old sessions from the session id cache */
  const char* servername;
  struct string session;		// a cookie sent during the handshake, so if a client comes back later, we can save work
  struct string mycert[MAXCERT];	// my own cert, maybe an intermediate cert, and a ca cert; sent during handshake
  struct string theircert[MAXCERT];
  struct string message;		// the packet we are currently trying to read or write
  size_t ofsinmessage;
  char scratch[2048];
  ssize_t (*_read)(uintptr_t handle,char* buf,size_t len);
  ssize_t (*_write)(uintptr_t handle,const char* buf,size_t len);
  int (*_close)(uintptr_t handle);
  int (*readcert)(struct ssl_context* sc);	// use sc->servername to read cert into sc->mycert
    // return 0 for success, enum alerttype otherwise
  uint16_t cipher,compressionmethod;
};

/* Put servername into ssl_context, set empty session. */
void init_tls_context_norandom(struct ssl_context* sc, const char* servername);

/* Put servername into ssl_context, and fill random bytes from
 * /dev/urandom. Return 0 if OK, -1 if /dev/urandom failed */
int init_tls_context(struct ssl_context* sc, const char* servername);

/* Generate a client hello inside a handshake packet using the
 * servername and session data from the context, return number of bytes
 * written to dest.  Call with dest=NULL to get needed buffer size. */
size_t fmt_tls_clienthello(char* dest, struct ssl_context* sc);

/* The response to a client hello consists of several packets:
   1. server hello
   2. certificate
  [3. server key exchange for a DHE cipher suite]
   4. server hello done */

/* Generate a server hello from a client hello that came in, return
 * number of bytes written to dest.
 * Call with dest=NULL to get needed buffer size.
 * Returns (size_t)-1 if the client hello is not complete,
 * (size_t)-2 if the client hello is invalid
 * if the client helo is valid but has no common ciphers, write an alert
 * and return length of alert (7) */
size_t fmt_tls_serverhello(char* dest,const char* clienthelo,size_t len,struct ssl_context* sc);

/* 
 * Allocate a buffer that can hold all the X.509 certificates plus 3
 * bytes per certificate plus 12 bytes for the headers.  Write the
 * certificates to buf+12 using fmt_tls_handshake_cert.  Then write
 * the header to buf using fmt_tls_handshake_certs_header; give it the
 * sum of the return values of fmt_tls_handshake_cert as len.
 */
size_t fmt_tls_handshake_cert(char* dest,const char* cert,size_t len);
size_t fmt_tls_handshake_certs_header(char* dest,size_t len_of_certs);

size_t fmt_tls_serverhellodone(char* dest);

size_t scan_tls_serverhello(const char* buf,size_t len,struct ssl_context* sc);

enum alertlevel {
  WARNING=1,
  FATAL=2
};

enum alerttype {
  CLOSE_NOTIFY=0,
  UNEXPECTED_MESSAGE=10,
  BAD_RECORD_MAC=20,
  DECRYPTION_FAILED=21,
  RECORD_OVERFLOW=22,
  DECOMPRESSION_FAILURE=30,
  HANDSHAKE_FAILURE=40,
  NO_CERT=41,
  BAD_CERT=42,
  UNSUPPORTED_CERT=43,
  CERT_REVOKED=44,
  CERT_EXPIRED=45,
  CERT_UNKNOWN=46,
  ILLEGAL_PARAMETER=47,
  UNKNOWN_CA=48,
  ACCESS_DENIED=49,
  DECODE_ERROR=50,
  DECRYPT_ERROR=51,
  EXPORT_RESTRICTION=60,
  PROTOCOL_VERSION=70,
  INSUFFICIENT_SECURITY=71,
  INTERNAL_ERROR=80,
  USER_CANCELED=90,
  NO_RENEGOTIATION=100,
  UNSUPPORTED_EXT=110
};

/* Generate a TLS alert (only the alert!) */
size_t fmt_tls_alert(char* dest,enum alertlevel level,enum alerttype type);

/* Generate a TLS alert with outer header */
size_t fmt_tls_alert_pkt(char* dest,enum alertlevel level,enum alerttype type);

enum contenttype {
  CHANGE_CIPHER_SPEC=20,
  ALERT=21,
  HANDSHAKE=22,
  APPLICATION_DATA=23
};

size_t fmt_tls_packet(char* dest,enum contenttype ct, size_t len);

enum ciphers {
  TLS_RSA_WITH_AES_256_CBC_SHA256=0x3d,
  TLS_RSA_WITH_AES_256_CBC_SHA=0x35,
};

/* return the desirability of a cipher (number >= 0)
 *   or -1 if the cipher is not supported
 * the higher the number, the less desirable is the cipher */
int tls_cipherprio(uint16_t cipher);

typedef enum {
  OK=0,
  IOFAIL=-1,		// I/O error
  WANTREAD=-2,		// socket was non-blocking; wait for read event
  WANTWRITE=-3,		// socket was non-blocking; wait for write event
  OOM=-4,		// out of memory
  PROTOCOLFAIL=-5,	// received invalid packets
  NEGOTIATIONFAIL=-6,	// no common ciphers / compression methods
  CRYPTOFAIL=-7,	// cryptographic failure (weak key detected or so)
  CERTFAIL=-8,		// certificate validation failed
  YOUSUCK=-42,		// user-supplied callbacks violated protocol
} tls_error_code;

tls_error_code tls_connect(uintptr_t fd,struct ssl_context* sc);
tls_error_code tls_accept(uintptr_t fd,struct ssl_context* sc);

/* these are internal helpers */
tls_error_code tls_dowrite(uintptr_t fd,struct ssl_context* sc);
tls_error_code tls_doread(uintptr_t fd,struct ssl_context* sc);
tls_error_code tls_checkalert(struct ssl_context* sc);

#endif
