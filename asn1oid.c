#include <string.h>
#include "asn1.h"

#define ENTRY(a,b,c) { sizeof(a)-1, a, b, c }

const struct oidlookup oid2string[] = {

  /* naming attribute OIDs */
  ENTRY("\x55\x04\x03", "commonName", X509_ATTR_COMMONNAME),
  ENTRY("\x55\x04\x04", "surname", X509_ATTR_SURNAME),
  ENTRY("\x55\x04\x05", "serialNumber", X509_ATTR_SERIALNUMBER),
  ENTRY("\x55\x04\x06", "countryName", X509_ATTR_COUNTRY),
  ENTRY("\x55\x04\x07", "localityName", X509_ATTR_LOCALITY),
  ENTRY("\x55\x04\x08", "stateOrProvinceName", X509_ATTR_STATEPROVINCE),
  ENTRY("\x55\x04\x09", "street", X509_ATTR_STREET),
  ENTRY("\x55\x04\x0a", "organizationName", X509_ATTR_ORG),
  ENTRY("\x55\x04\x0b", "organizationalUnitName", X509_ATTR_ORGUNIT),
  ENTRY("\x55\x04\x0c", "title", X509_ATTR_TITLE),
  ENTRY("\x55\x04\x0d", "description", X509_ATTR_DESC),
  ENTRY("\x55\x04\x2a", "givenName", X509_ATTR_GIVENNAME),
  ENTRY("\x55\x04\x2b", "initials", X509_ATTR_INITIALS),
  ENTRY("\x55\x04\x2c", "generationQualifier", X509_ATTR_GENERATIONQUALIFIER),
  ENTRY("\x55\x04\x2d", "uniqueIdentifier", X509_ATTR_UNIQID),
  ENTRY("\x55\x04\x2e", "dnQualifier", X509_ATTR_DNQUALIFIER),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", "emailAddress", X509_ATTR_EMAIL),

  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", "signedData", X509_SIGNEDDATA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01", "data", X509_DATA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03", "contentType", X509_CONTENTTYPE),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04", "messageDigest", X509_MESSAGEDIGEST),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05", "signingTime", X509_SIGNINGTIME),
  ENTRY("\x60\x86\x48\x01\x86\xf8\x42\x01\x01", "netscapeCertType", X509_NETSCAPE_CERTTYPE),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0f", "smimeCapabilities", X509_SMIME_CAPABILITIES),

  /* X.509v3 extension OIDs */
  ENTRY("\x55\x1d\x0e", "subject_key_identifier", X509_EXT_SUBJKEYID),
  ENTRY("\x55\x1d\x0f", "key_usage", X509_EXT_KEYUSAGE),
  ENTRY("\x55\x1d\x10", "private_key_usage_period", X509_EXT_PRIVKEYUSAGEPERIOD),
  ENTRY("\x55\x1d\x11", "subject_alt_name", X509_EXT_SUBJALTNAME),
  ENTRY("\x55\x1d\x12", "issuer_alt_name", X509_EXT_ISSUERALTNAME),
  ENTRY("\x55\x1d\x13", "basic_constraints", X509_EXT_BASICCONSTRAINTS),
  ENTRY("\x55\x1d\x14", "crl_number", X509_EXT_CRL_NUMBER),
  ENTRY("\x55\x1d\x15", "reasonCode", X509_EXT_REASONCODE),
  ENTRY("\x55\x1d\x17", "instruction_code", X509_EXT_INSTRUCTIONCODE),
  ENTRY("\x55\x1d\x18", "invalidity_date", X509_EXT_INVALIDITYDATE),
  ENTRY("\x55\x1d\x1b", "delta_crl_indicator", X509_EXT_DELTA_CRL_INDICATOR),
  ENTRY("\x55\x1d\x1c", "issuing_distribution_point", X509_EXT_ISSUING_DISTRIBUTION_POINT),
  ENTRY("\x55\x1d\x1e", "name_constraints", X509_EXT_NAME_CONSTRAINTS),
  ENTRY("\x55\x1d\x1f", "crl_distribution_points", X509_EXT_CRL_DISTRIBUTION_POINTS),
  ENTRY("\x55\x1d\x20", "certificate_policies", X509_EXT_CERT_POLICIES),
  ENTRY("\x55\x1d\x23", "authority_key_identifier", X509_EXT_AUTH_KEY_ID),
  ENTRY("\x55\x1d\x25", "ext_key_usage", X509_EXT_KEY_USAGE),

  /* X.509 algorithms */
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", "rsaEncryption", X509_ALG_RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02", "md2WithRSAEncryption", X509_ALG_MD2RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x03", "md4WithRSAEncryption", X509_ALG_MD4RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", "md5WithRSAEncryption", X509_ALG_MD5RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", "sha1WithRSAEncryption", X509_ALG_SHA1RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", "sha256WithRSAEncryption", X509_ALG_SHA256RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", "sha384WithRSAEncryption", X509_ALG_SHA384RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", "sha512WithRSAEncryption", X509_ALG_SHA512RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e", "sha224WithRSAEncryption", X509_ALG_SHA224RSA),
  ENTRY("\x2b\x0e\x03\x02\x03", "md5WithRSA", X509_ALG_MD5RSA),
  ENTRY("\x2b\x0e\x03\x02\x06", "des_ecb", X509_ALG_DES_ECB),
  ENTRY("\x2b\x0e\x03\x02\x07", "des_cbc", X509_ALG_DES_CBC),
  ENTRY("\x2b\x0e\x03\x02\x08", "des_ofb64", X509_ALG_DES_OFB64),
  ENTRY("\x2b\x0e\x03\x02\x08", "des_cfb64", X509_ALG_DES_CFB64),
  ENTRY("\x2b\x0e\x03\x02\x0b", "rsaSignature", X509_ALG_RSASIGNATURE),
  ENTRY("\x2b\x0e\x03\x02\x0c", "dsa_2", X509_ALG_DSA_2),
  ENTRY("\x2b\x0e\x03\x02\x0d", "dsaWithSha", X509_ALG_DSASHA),
  ENTRY("\x2b\x0e\x03\x02\x0f", "shaWithRSA", X509_ALG_SHARSA),
  ENTRY("\x2b\x0e\x03\x02\x11", "des_ede_ecb", X509_ALG_DES_EDE_ECB),
  ENTRY("\x2b\x0e\x03\x02\x12", "sha", X509_ALG_SHA),
  ENTRY("\x2b\x0e\x03\x02\x1a", "sha1", X509_ALG_SHA1),
  ENTRY("\x2b\x0e\x03\x02\x1b", "dsaWithSHA1_2", X509_ALG_DSASHA1_2),
  ENTRY("\x2b\x0e\x03\x02\x1d", "sha1WithRSA", X509_ALG_SHA1RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x02\x04", "md4", X509_ALG_MD4),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x02\x05", "md5", X509_ALG_MD5),
  ENTRY("\x2b\x24\x03\x02\x01", "ripemd", X509_ALG_RIPEMD),
  ENTRY("\x60\x86\x48\x01\x65\x03\x04\x01\x2a", "aes256_cbc", X509_ALG_AES256_CBC),
  ENTRY("\x2a\x85\x03\x02\x02\x09", "GOST R 34.11-94", X509_ALG_GOSTR3411_94),
  ENTRY("\x2a\x85\x03\x02\x02\x15", "GOST 28147-89", X509_ALG_GOST28147_89),
  ENTRY("\x60\x86\x48\x01\x65\x03\x04\x01\x16", "aes192_cbc", X509_ALG_AES192_CBC),
  ENTRY("\x60\x86\x48\x01\x65\x03\x04\x01\x02", "aes128_cbc", X509_ALG_AES128_CBC),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x03\x07", "des_ede3_cbc", X509_ALG_DES_EDE3_CBC),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x03\x02", "rc2_cbc", X509_ALG_RC2_CBC),

};

#undef ENTRY

size_t lookupoid(const char* oid,size_t l) {
  size_t i;
  for (i=0; i<sizeof(oid2string)/sizeof(oid2string[0]); ++i)
    if (oid2string[i].l==l && memcmp(oid,oid2string[i].oid,l)==0)
      return i;
  return -1;
}

