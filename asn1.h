/* parser and formatter for ASN.1 DER encoding.
 * The parser can read BER encoding, too. */

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
  OCTET_STRING=4,
  ENUMERATED=10,
  SEQUENCE_OF=16,
  SET_OF=17,
};

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 tag */
int fmt_asn1tag(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,unsigned long tag);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 length */
int fmt_asn1length(char* dest,unsigned long l);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER.  This only does the payload, not the tag
 * and length headers! */
int fmt_asn1intpayload(char* dest,unsigned long l);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER.  This only does the payload, not the tag
 * and length headers! */
int fmt_asn1sintpayload(char* dest,signed long l);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER or ENUMERATED. */
int fmt_asn1int(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,unsigned long l);

/* write int in least amount of bytes, return number of bytes */
/* as used in ASN.1 INTEGER or ENUMERATED. */
int fmt_asn1sint(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,signed long l);

/* write any data type that does not require transformation in the least
 * amount of bytes, return number of bytes */
/* as used in ASN.1 OCTET STRING, SEQUENCE etc. */
/* does not wrote the payload itself, just the header!  First construct
 * the sequence/octet string so you know the length, then use
 * fmt_asn1transparent to write the header before it */
int fmt_asn1transparent(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,unsigned long l);

/* write string in least amount of bytes, return number of bytes */
/* as used in ASN.1 OCTET STRING. */
int fmt_asn1string(char* dest,enum asn1_tagclass tc,enum asn1_tagtype tt,enum asn1_tag tag,const char* c,unsigned long l);

/* write ASN.1 OCTET STRING */
#define fmt_asn1OCTETSTRING(dest,c,l) fmt_asn1string(dest,UNIVERSAL,PRIMITIVE,OCTET_STRING,c,l);

/* write ASN.1 INTEGER */
#define fmt_asn1INTEGER(dest,l) fmt_asn1int(dest,UNIVERSAL,PRIMITIVE,INTEGER,l);

/* write ASN.1 BOOLEAN */
#define fmt_asn1BOOLEAN(dest,l) fmt_asn1int(dest,UNIVERSAL,PRIMITIVE,BOOLEAN,l);

/* write ASN.1 ENUMERATED */
#define fmt_asn1ENUMERATED(dest,l) fmt_asn1int(dest,UNIVERSAL,PRIMITIVE,ENUMERATED,l);

/* write ASN.1 SEQUENCE */
#define fmt_asn1SEQUENCE(dest,l) fmt_asn1transparent(dest,UNIVERSAL,CONSTRUCTED,SEQUENCE_OF,l);

/* write ASN.1 SET */
#define fmt_asn1SET(dest,l) fmt_asn1transparent(dest,UNIVERSAL,CONSTRUCTED,SET_OF,l);


/* conventions for the parser routines:
 *   src points to the first byte to parse
 *   max points to the first byte behind the buffer
 *   the return value is the number of bytes parsed or 0 for parse error */

/* parse ASN.1 tag into a tag class, tag type and tag number */
int scan_asn1tag(const char* src,const char* max,
		 enum asn1_tagclass* tc,enum asn1_tagtype* tt, unsigned long* tag);

/* parse ASN.1 length */
int scan_asn1length(const char* src,const char* max,unsigned long* length);

/* parse ASN.1 integer with tag and length */
int scan_asn1int(const char* src,const char* max,
		 enum asn1_tagclass* tc,enum asn1_tagtype* tt, unsigned long* tag,
		 long* l);

/* parse raw integer (payload after tag and length); internal helper */
int scan_asn1rawint(const char* src,const char* max,unsigned int len,long* i);

/* parse string with tag and length.
 * Points s to the first byte in the string, and writes the length of
 * the string to l. */
int scan_asn1string(const char* src,const char* max,
		    enum asn1_tagclass* tc,enum asn1_tagtype* tt,unsigned long* tag,
		    const char** s,unsigned long* l);

/* the following expect a specific universal type and return a parse
 * error if the tag does not match that type */
int scan_asn1BOOLEAN(const char* src,const char* max,unsigned long* l);
int scan_asn1INTEGER(const char* src,const char* max,signed long* l);
int scan_asn1ENUMERATED(const char* src,const char* max,unsigned long* l);
int scan_asn1STRING(const char* src,const char* max,const char** s,unsigned long* l);
int scan_asn1SEQUENCE(const char* src,const char* max,unsigned long* len);
int scan_asn1SET(const char* src,const char* max,unsigned long* len);
