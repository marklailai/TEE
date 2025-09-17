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
#include <openssl/crypto.h>
#include <stdint.h>
#include <stddef.h>

int enclave_sm4_encrypt_cbc(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, size_t ciphertext_len)
{
    OPENSSL_init_crypto(0, NULL);
    if (plaintext == NULL || key == NULL || iv == NULL || ciphertext == NULL)
    {
        return -1; // Invalid input pointers
    }

    // SM4 block size is 16 bytes
    const size_t block_size = 16;
    size_t required_len = plaintext_len + block_size;

    // Ensure output buffer is large enough
    if (ciphertext_len < required_len)
    {
        return -2; // Output buffer too small
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -3; // Failed to create context
    }

    int ret = -1;
    int len = 0;
    int out_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv) != 1)
    {
        goto exit;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        goto exit;
    }
    out_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        goto exit;
    }
    out_len += len;

    ret = 0; // Success
    
exit:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}
