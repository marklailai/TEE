#ifndef SM_CRYPTO_DEFS_H
#define SM_CRYPTO_DEFS_H

/* 
 * NOTE: The values in this file must be kept in sync with the
 * literal values used in the switchless.edl file.
 */

// Maximum size for an SM2 signature (in bytes)
#define SM2_MAX_SIGNATURE_LEN 256

// Maximum size for an SM2 public key (in bytes)
#define SM2_MAX_PUB_KEY_LEN 128

// Maximum size for an SM2 private key (in bytes)
#define SM2_MAX_PRIV_KEY_LEN 64

#endif // SM_CRYPTO_DEFS_H
