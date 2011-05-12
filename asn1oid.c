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
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02", "md2WithRSAEncryption", X509_ALG_MD2RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x03", "md4WithRSAEncryption", X509_ALG_MD4RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", "md5WithRSAEncryption", X509_ALG_MD5RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", "SHA1WithRSAEncryption", X509_ALG_SHA1RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", "SHA256WithRSAEncryption", X509_ALG_SHA256RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c", "SHA384WithRSAEncryption", X509_ALG_SHA384RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d", "SHA512WithRSAEncryption", X509_ALG_SHA512RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e", "SHA224WithRSAEncryption", X509_ALG_SHA224RSA),
  ENTRY("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", "rsaEncryption", X509_ALG_RSA),

};

#undef ENTRY

size_t lookupoid(const char* oid,size_t l) {
  size_t i;
  for (i=0; i<sizeof(oid2string)/sizeof(oid2string[0]); ++i)
    if (oid2string[i].l==l && memcmp(oid,oid2string[i].oid,l)==0)
      return i;
  return -1;
}

