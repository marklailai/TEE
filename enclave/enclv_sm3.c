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
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sm3.h>
#include <stdint.h>
#include <stddef.h>

int enclave_sm3_hash(const uint8_t* message, size_t message_len, uint8_t* hash_output)
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
    
    if (message == NULL) {
        return -1; // message is NULL
    }
    if (hash_output == NULL) {
        return -2; // hash_output is NULL  
    }
    if (message_len == 0) {
        return -3; // message_len is 0
    }
    
    // Check if SM3 is available
    const EVP_MD *sm3_md = EVP_sm3();
    if (sm3_md == NULL) {
        return -4; // SM3 not available
    }
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return -5;
    }
    
    if (EVP_DigestInit_ex(md_ctx, sm3_md, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -6;
    }
    
    if (EVP_DigestUpdate(md_ctx, message, message_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -7;
    }
    
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(md_ctx, hash_output, &hash_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -8;
    }
    
    // Verify we got the expected 32-byte SM3 hash
    if (hash_len != 32) {
        EVP_MD_CTX_free(md_ctx);
        return -9;
    }
    
    EVP_MD_CTX_free(md_ctx);
    return 0;
}
