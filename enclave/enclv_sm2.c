/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "switchless_t.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include <stddef.h>

static EVP_PKEY *sm2_key = NULL;

int enclave_sm2_keygen()
{
    OPENSSL_init_crypto(0, NULL);

    // Free existing key if present
    if (sm2_key != NULL)
    {
        EVP_PKEY_free(sm2_key);
        sm2_key = NULL;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (pctx == NULL)
    {
        return -1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    if (EVP_PKEY_keygen(pctx, &sm2_key) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int enclave_sm2_generate_key_pair(uint8_t *public_key, size_t *public_key_len, uint8_t *private_key, size_t *private_key_len)
{
    if (public_key == NULL || public_key_len == NULL || private_key == NULL || private_key_len == NULL)
    {
        return -1;
    }

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    BIGNUM *priv = NULL;
    unsigned char *pub_buf = NULL;
    size_t pub_len = 0;
    int ret = -1;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL);
    if (pctx == NULL)
    {
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        goto cleanup;
    }

    if (EVP_PKEY_keygen(pctx, &key) <= 0 || key == NULL)
    {
        goto cleanup;
    }

    // Extract private key
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &priv) <= 0)
    {
        goto cleanup;
    }

    int priv_len = BN_bn2bin(priv, private_key);
    if (priv_len == 0)
    { // BN_bn2bin returns 0 on error
        goto cleanup;
    }
    *private_key_len = priv_len;

    // Extract public key length
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_len) <= 0)
    {
        goto cleanup;
    }

    // Sanity check to prevent large allocation
    if (pub_len > 1024)
    { // Adjust based on expected max size
        goto cleanup;
    }

    pub_buf = OPENSSL_malloc(pub_len);
    if (pub_buf == NULL)
    {
        goto cleanup;
    }

    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len, &pub_len) <= 0)
    {
        goto cleanup;
    }

    if (pub_len > *public_key_len)
    {
        goto cleanup;
    }

    memcpy(public_key, pub_buf, pub_len);
    *public_key_len = pub_len;

    ret = 0;

cleanup:
    if (priv != NULL)
        BN_free(priv);
    if (pub_buf != NULL)
        OPENSSL_free(pub_buf);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (key != NULL)
        EVP_PKEY_free(key);

    return ret;
}

int enclave_sm2_sign(const uint8_t* digest, size_t digest_len, uint8_t* signature, size_t* signature_len)
{
    if (digest == NULL || signature == NULL || signature_len == NULL)
    {
        return -1;
    }

    if (digest_len == 0)
    {
        return -1;
    }

    // Ensure SM2 key is available
    if (sm2_key == NULL)
    {
        if (enclave_sm2_keygen() != 0)
        {
            return -1;
        }
        // Double check that key was properly generated
        if (sm2_key == NULL)
        {
            return -1;
        }
    }

    EVP_PKEY_CTX *pctx = NULL;
    int ret = -1;

    pctx = EVP_PKEY_CTX_new(sm2_key, NULL);
    if (pctx == NULL)
    {
        goto cleanup;
    }

    if (EVP_PKEY_sign_init(pctx) <= 0)
    {
        goto cleanup;
    }

    if (EVP_PKEY_sign(pctx, signature, signature_len, digest, digest_len) <= 0)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);

    return ret;
}


