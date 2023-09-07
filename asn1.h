#ifndef ASN1_H
#define ASN1_H

/* parser and formatter for ASN.1 DER encoding.
 * The parser can read BER encoding, too. */

#include <stddef.h>

enum asn1_tagclass {
  UNIVERSAL=(0<<6),
  APPLICATION=(1<<6),
  PRIVATE=(2<<6),
  CONTEXT_SPECIFIC=(3<<6)
};

enum asn1_tagtype {
  PRIMITIVE=(0<<5),
  CONSTRUCTED=(1<<5)
};

enum asn1_tag {
  BOOLEAN=1,
  INTEGER=2,
  BIT_STRING=3,
  OCTET_STRING=4,
  _NULL=5,
  OBJECT_IDENTIFIER=6,
  ENUMERATED=10,
  SEQUENCE_OF=16,
  SET_OF=17,
  PrintableString=19,
  IA5String=22,
  UTCTIME=23
};

/* write variable length integer in the encoding used in tag and oid */
size_t fmt_asn1tagint(char* dest,unsigned long val);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tag */
size_t fmt_asn1tag(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,
		   unsigned long tag);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 length */
size_t fmt_asn1length(char* dest,size_t l);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER.  This only does the payload, not the tag
 * and length headers! */
size_t fmt_asn1intpayload(char* dest,unsigned long val);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER.  This only does the payload, not the tag
 * and length headers! */
size_t fmt_asn1sintpayload(char* dest,signed long val);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER or ENUMERATED. */
size_t fmt_asn1int(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,
		   enum asn1_tag tag,unsigned long val);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER or ENUMERATED. */
size_t fmt_asn1sint(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,
		    enum asn1_tag tag,signed long val);

/* write any data type that does not require transformation in the least
 * amount of bytes, return number of bytes */
/* as used in ASN.1 OCTET STRING, SEQUENCE etc. */
/* does not wrote the payload itself, just the header!  First construct
 * the sequence/octet string so you know the length, then use
 * fmt_asn1transparent to write the header before it */
size_t fmt_asn1transparent(char* dest,enum asn1_tagclass tc,
			   enum asn1_tagtype tt,enum asn1_tag tag,size_t len);

/* write string in least amount of bytes, return number of bytes */
/* as used in ASN.1 OCTET STRING. */
size_t fmt_asn1string(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,
		      enum asn1_tag tag,const char* c,size_t l);

/* same but for bitstrings.
 * l in this case means the number of BITS in c, not bytes */
size_t fmt_asn1bitstring(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,
			 enum asn1_tag tag,const char* c,size_t l);

/* write ASN.1 OCTET STRING */
#define fmt_asn1OCTETSTRING(dest,c,l) fmt_asn1string(dest,UNIVERSAL,PRIMITIVE,OCTET_STRING,c,l)

/* write ASN.1 INTEGER */
#define fmt_asn1INTEGER(dest,l) fmt_asn1int(dest,UNIVERSAL,PRIMITIVE,INTEGER,l)

/* write ASN.1 BOOLEAN */
#define fmt_asn1BOOLEAN(dest,l) fmt_asn1sint(dest,UNIVERSAL,PRIMITIVE,BOOLEAN,l ? -1 : 0)

/* write ASN.1 ENUMERATED */
#define fmt_asn1ENUMERATED(dest,l) fmt_asn1int(dest,UNIVERSAL,PRIMITIVE,ENUMERATED,l)

/* write ASN.1 SEQUENCE */
#define fmt_asn1SEQUENCE(dest,l) fmt_asn1transparent(dest,UNIVERSAL,CONSTRUCTED,SEQUENCE_OF,l)

/* write ASN.1 SET */
#define fmt_asn1SET(dest,l) fmt_asn1transparent(dest,UNIVERSAL,CONSTRUCTED,SET_OF,l)

size_t fmt_asn1OID(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const size_t* array,size_t len);


/* conventions for the parser routines:
 *   src points to the first byte to parse
 *   max points to the first byte behind the buffer
 *   the return value is the number of bytes parsed or 0 for parse error */

/* parse ASN.1 variable length integer as used in tag and oid */
size_t scan_asn1tagint(const char* src,const char* max,unsigned long* val);

/* parse ASN.1 tag into a tag class, tag type and tag number */
size_t scan_asn1tag(const char* src,const char* max,
		    enum asn1_tagclass* tc,enum asn1_tagtype* tt, unsigned long* tag);

/* parse ASN.1 length */
/* only return success if source buffer is large enough to hold length bytes */
size_t scan_asn1length(const char* src,const char* max,size_t* length);

/* Same but does not check the source buffer is large enough to hold
 * length bytes. Useful to find out how many more bytes we need to read
 * from network */
size_t scan_asn1length_nolengthcheck(const char* src,const char* max, size_t* length);

/* helper for scan_asn1INT, scan_asn1ENUMERATED and scan_asn1BOOLEAN */
size_t scan_asn1int(const char* src,const char* max,
		    enum asn1_tagclass* tc,enum asn1_tagtype* tt, unsigned long* tag,
		    long* val);

/* parse raw integer (payload after tag and length); internal helper */
size_t scan_asn1rawint(const char* src,const char* max,size_t len,long* val);

/* parse string with tag and length.
 * Points s to the first byte in the string, and writes the length of
 * the string to l. */
size_t scan_asn1string(const char* src,const char* max,
		    enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,
		    const char** s,size_t* l);

/* the following expect a specific universal type and return a parse
 * error if the tag does not match that type */
size_t scan_asn1BOOLEAN(const char* src,const char* max,int* l);
size_t scan_asn1INTEGER(const char* src,const char* max,signed long* l);
size_t scan_asn1ENUMERATED(const char* src,const char* max,unsigned long* l);
size_t scan_asn1STRING(const char* src,const char* max,const char** s,size_t* l);
size_t scan_asn1BITSTRING(const char* src,const char* max,const char** s,size_t* l);
/* note: these only parse the header. src + return value points to first element */
size_t scan_asn1SEQUENCE(const char* src,const char* max,size_t* len);
/* scan_asn1SEQUENCE will only return success if the header and the
 * whole contents fit into src..max; this function will only parse the
 * outer sequence header and return the number of bytes it say it wants.
 * For finding out how much more data you need to read from the socket. */
size_t scan_asn1SEQUENCE_nolengthcheck(const char* src,const char* max,size_t* len);
size_t scan_asn1SET(const char* src,const char* max,size_t* len);

/* scan an ASN.1 OID and put the numbers into array.
 * Return numbers of bytes parsed or 0 on error.
 * Put at most arraylen longs into array; if the OID is longer, or if array is NULL, return real number in arraylen and return 0
 * If 0 is returned and arraylen is also 0, there was a parse error */
size_t scan_asn1oid(const char* src,const char* max,size_t* array,size_t* arraylen);
/* internal helper, assumes you already read tag and length and max=src+length */
/* call with *arraylen = sizeof(array)/sizeof(array[0]) */
/* returns needed array size in *arraylen */
/* rule of thumb: (number of bytes in input + 1) needed */
size_t scan_asn1rawoid(const char* src,const char* max,size_t* array,size_t* arraylen);

struct string {
  size_t l;
  const char* s;
};

struct oid {
  size_t l;
  size_t* a;
};

enum x509_oid {
  X509_ATTR_COMMONNAME, X509_ATTR_SURNAME, X509_ATTR_SERIALNUMBER,
  X509_ATTR_COUNTRY, X509_ATTR_LOCALITY, X509_ATTR_STATEPROVINCE,
  X509_ATTR_STREET, X509_ATTR_ORG, X509_ATTR_ORGUNIT, X509_ATTR_TITLE,
  X509_ATTR_DESC, X509_ATTR_GIVENNAME, X509_ATTR_INITIALS,
  X509_ATTR_GENERATIONQUALIFIER, X509_ATTR_UNIQID, X509_ATTR_DNQUALIFIER,
  X509_ATTR_EMAIL,

  X509_SIGNEDDATA, X509_DATA, X509_CONTENTTYPE, X509_MESSAGEDIGEST, X509_SIGNINGTIME,
  X509_PKCS2, X509_NETSCAPE_CERTTYPE, X509_SMIME_CAPABILITIES,

  X509_EXT_SUBJKEYID, X509_EXT_KEYUSAGE, X509_EXT_PRIVKEYUSAGEPERIOD,
  X509_EXT_SUBJALTNAME, X509_EXT_ISSUERALTNAME, X509_EXT_BASICCONSTRAINTS,
  X509_EXT_CRL_NUMBER, X509_EXT_REASONCODE, X509_EXT_INSTRUCTIONCODE,
  X509_EXT_INVALIDITYDATE, X509_EXT_DELTA_CRL_INDICATOR,
  X509_EXT_ISSUING_DISTRIBUTION_POINT, X509_EXT_NAME_CONSTRAINTS,
  X509_EXT_CRL_DISTRIBUTION_POINTS, X509_EXT_CERT_POLICIES,
  X509_EXT_AUTH_KEY_ID, X509_EXT_KEY_USAGE,

  X509_ALG_MD2RSA, X509_ALG_MD4RSA, X509_ALG_MD5RSA, X509_ALG_SHA1RSA,
  X509_ALG_SHA256RSA, X509_ALG_SHA384RSA, X509_ALG_SHA512RSA,
  X509_ALG_SHA224RSA, X509_ALG_RSA, X509_ALG_MD4, X509_ALG_MD5,

  X509_ALG_DES_ECB, X509_ALG_DES_CBC, X509_ALG_DES_OFB64,
  X509_ALG_DES_CFB64, X509_ALG_RSASIGNATURE, X509_ALG_DSA_2,
  X509_ALG_DSASHA, X509_ALG_SHARSA, X509_ALG_DES_EDE_ECB, X509_ALG_SHA,
  X509_ALG_SHA1, X509_ALG_DSASHA1_2, X509_ALG_AES256_CBC,
  X509_ALG_AES192_CBC, X509_ALG_AES128_CBC, X509_ALG_DES_EDE3_CBC,
  X509_ALG_RC2_CBC, X509_ALG_RIPEMD,

  X509_ALG_GOSTR3411_94, X509_ALG_GOST28147_89,
};

extern const struct oidlookup {
  size_t l;
  const char* oid,* name;
  enum x509_oid id;
} oid2string[];

size_t lookupoid(const char* oid,size_t l);

/* Generic parser and formatter routines: */
size_t scan_asn1generic(const char* src,const char* max,const char* fmt,...);
size_t fmt_asn1generic(char* dest,const char* fmt,...);
/* the format string works like this:
 *   'i'	parse INTEGER; next argument is a long* (scan) or unsigned long (fmt)
 *   'B'	parse BOOLEAN; next argument is an int* (scan) or int (fmt)
 *   '*'	(fmt only) next argument is an unsigned long, tag type is set to APPLICATION and tag is set to that argument
 *   '*'	(scan only) next argument is an unsigned long*; for next tag, expect tag type to be APPLICATION and write tag to this unsigned long*
 *   'b'	next argument is a struct string* but the length l in it is in bits, not bytes; if the length is not a multiple of 8, the unused bits are at the end of the last byte in the string
 *   'I'	(fmt only) next argument is struct string *, send as BIT_STRING
 *   'S'	(fmt only) next argument is struct string *, send as OCTET_STRING
 *   's'	(fmt only) next argument is const char*, use strlen and send as OCTET_STRING
 *   's'	(scan only) next argument is struct string*, parse OCTET_STRING into it
 *   'o'	(fmt only) next argument is struct oid*, send OBJECT_IDENTIFIER
 *   'o'	(scan only) next argument is struct string*, parse raw OBJECT_IDENTIFIER into it; you have to call scan_asn1rawoid on contents of string to process further
 *   '['	start set
 *   ']'	end set
 *   '{'	start sequence
 *   '}'	end sequence
 *   '?'	from here till end of input / set / sequence is optional and can be missing
 *   'u'	(scan only) next argument is time_t*, parse UTCTIME into it
 *   'p'	(scan only) like 's' but check that contents of string is printable
 *   'a'	(scan only) like 's' but check that contents of string is ascii
 *   '!'	(scan only) next argument is struct string*, fill in region until end of current sequence / set (for optional data)
 *   'c'	context specific value (tag class PRIVATE, type CONSTRUCTED, tag taken from unsigned long arg / written to unsigned long* argument)
 */

#endif
