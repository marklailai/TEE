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

#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include <sys/time.h>
#include <string.h>
#include "enclave.h"
#include "secgear_uswitchless.h"
#include "secgear_shared_memory.h"
#include "common/sm_crypto_defs.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "switchless_u.h"

#define BUF_LEN 32

// Temporary test method for SM2 key generation
void test_sm2_keygen()
{
    printf("=== SM2 Key Generation Test ===\n");
    
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio_out = NULL;
    
    // Create context for SM2 key generation
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        printf("Failed to create EVP_PKEY_CTX\n");
        return;
    }
    
    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        printf("Failed to initialize key generation\n");
        goto cleanup;
    }
    
    // Set curve to SM2
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2) <= 0) {
        printf("Failed to set SM2 curve\n");
        goto cleanup;
    }
    
    // Generate key pair
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        printf("Failed to generate SM2 key pair\n");
        goto cleanup;
    }
    
    printf("SM2 key pair generated successfully!\n");
    
    // Print public key
    bio_out = BIO_new(BIO_s_mem());
    if (bio_out && PEM_write_bio_PUBKEY(bio_out, pkey)) {
        char *pub_key_data;
        long pub_key_len = BIO_get_mem_data(bio_out, &pub_key_data);
        printf("Public Key:\n%.*s\n", (int)pub_key_len, pub_key_data);
    }
    BIO_free(bio_out);
    
    // Print private key
    bio_out = BIO_new(BIO_s_mem());
    if (bio_out && PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, NULL, NULL)) {
        char *priv_key_data;
        long priv_key_len = BIO_get_mem_data(bio_out, &priv_key_data);
        printf("Private Key:\n%.*s\n", (int)priv_key_len, priv_key_data);
    }
    
cleanup:
    if (bio_out) BIO_free(bio_out);
    if (pkey) EVP_PKEY_free(pkey);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    printf("=== End SM2 Key Generation Test ===\n\n");
}

int main()
{
    // Run SM2 key generation test
    test_sm2_keygen();
    
    int  retval = 0;
    char *path = PATH;
    char buf[BUF_LEN];
    cc_enclave_t context = {0};
    cc_enclave_result_t res = CC_FAIL;

    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find enclave.sign.so");
            goto end;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/enclave.signed.so")) {
            printf("Failed to strcat enclave.sign.so path");
            goto end;
        }
        (void)strcat(real_p, "/enclave.signed.so");
    }

    /* switchless configuration */
    cc_sl_config_t sl_cfg = CC_USWITCHLESS_CONFIG_INITIALIZER;
    sl_cfg.num_tworkers = 2; /* 2 tworkers */
    sl_cfg.sl_call_pool_size_qwords = 2; /* 2 * 64 tasks */
    enclave_features_t features = {ENCLAVE_FEATURE_SWITCHLESS, (void *)&sl_cfg};

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, &features, 1, &context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        goto end;
    }

    char *shared_buf = (char *)cc_malloc_shared_memory(&context, BUF_LEN);
    if (shared_buf == NULL) {
        printf("Malloc shared memory failed.\n");
        goto error;
    }

    /* normal ecall */
    res = get_string(&context, &retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Normal ecall error\n");
    } else {
        printf("buf: %s\n", buf);
    }

    /* switchless ecall */
    res = get_string_switchless(&context, &retval, shared_buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        printf("Switchless ecall error\n");
    } else {
        printf("shared_buf: %s\n", shared_buf);
    }

    /* Tongsuo crypto tests */
    printf("\n--- Calling Tongsuo crypto functions in enclave ---\n");

    /* SM3 Test */
    const char* sm3_message = "Hello Tongsuo SM3 from secGear";
    size_t msg_len = strlen(sm3_message);
    
    // Allocate shared memory for input message
    char *sm3_msg_shared = (char *)cc_malloc_shared_memory(&context, msg_len + 1);
    if (sm3_msg_shared == NULL) {
        printf("Malloc sm3 message shared memory failed.\n");
        goto error;
    }
    memcpy(sm3_msg_shared, sm3_message, msg_len);
    
    // Allocate shared memory for output hash
    char *sm3_shared_buf = (char *)cc_malloc_shared_memory(&context, 32);
    if (sm3_shared_buf == NULL) {
        printf("Malloc sm3 shared memory failed.\n");
        cc_free_shared_memory(&context, sm3_msg_shared);
        goto error;
    }
    
    res = enclave_sm3_hash(&context, &retval, (const uint8_t*)sm3_msg_shared, msg_len, (uint8_t*)sm3_shared_buf);
    if (res != CC_SUCCESS || retval != 0) {
        printf("Enclave SM3 hash failed. res=%d, retval=%d\n", res, retval);
    } else {
        printf("SM3 Hash: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", (unsigned char)sm3_shared_buf[i]);
        }
        printf("\n");
    }
    cc_free_shared_memory(&context, sm3_shared_buf);
    cc_free_shared_memory(&context, sm3_msg_shared);

    /* SM4 Test */
    const char* sm4_plaintext = "Hello Tongsuo SM4 from secGear";
    size_t plaintext_len = strlen(sm4_plaintext);
    size_t ciphertext_len = plaintext_len + 16;
    
    // Allocate shared memory for all parameters
    char *sm4_plaintext_shared = (char *)cc_malloc_shared_memory(&context, plaintext_len + 1);
    uint8_t *sm4_key_shared = (uint8_t *)cc_malloc_shared_memory(&context, 16);
    uint8_t *sm4_iv_shared = (uint8_t *)cc_malloc_shared_memory(&context, 16);
    char *sm4_shared_buf = (char *)cc_malloc_shared_memory(&context, ciphertext_len);
    
    if (sm4_plaintext_shared == NULL || sm4_key_shared == NULL || sm4_iv_shared == NULL || sm4_shared_buf == NULL) {
        printf("Malloc sm4 shared memory failed.\n");
        if (sm4_plaintext_shared) cc_free_shared_memory(&context, sm4_plaintext_shared);
        if (sm4_key_shared) cc_free_shared_memory(&context, sm4_key_shared);
        if (sm4_iv_shared) cc_free_shared_memory(&context, sm4_iv_shared);
        if (sm4_shared_buf) cc_free_shared_memory(&context, sm4_shared_buf);
        goto error;
    }
    
    // Copy data to shared memory
    memcpy(sm4_plaintext_shared, sm4_plaintext, plaintext_len);
    memcpy(sm4_key_shared, "1234567890123456", 16);
    memcpy(sm4_iv_shared, "1234567890123456", 16);

    res = enclave_sm4_encrypt_cbc(&context, &retval, (const uint8_t*)sm4_plaintext_shared, plaintext_len, sm4_key_shared, sm4_iv_shared, (uint8_t*)sm4_shared_buf, ciphertext_len);
    if (res != CC_SUCCESS || retval != 0) {
        printf("Enclave SM4 encrypt failed. res=%d, retval=%d\n", res, retval);
    } else {
        printf("SM4 Ciphertext: ");
        for (int i = 0; i < ciphertext_len; i++) {
            printf("%02x", (unsigned char)sm4_shared_buf[i]);
        }
        printf("\n");
    }
    cc_free_shared_memory(&context, sm4_shared_buf);
    cc_free_shared_memory(&context, sm4_plaintext_shared);
    cc_free_shared_memory(&context, sm4_key_shared);
    cc_free_shared_memory(&context, sm4_iv_shared);

    /* SM2 Signing Test */
    uint8_t sm3_hash_for_sm2[32];
    /* First, get the SM3 hash of the message to be used in signing */
    res = enclave_sm3_hash(&context, &retval, (const uint8_t*)sm3_message, strlen(sm3_message), sm3_hash_for_sm2);
    if (res != CC_SUCCESS || retval != 0) {
        printf("Enclave SM3 hash for SM2 signing failed.\n");
        goto error;
    }

    size_t sm2_signature_len = 256; /* Max possible signature size */
    char *sm2_shared_buf = (char *)cc_malloc_shared_memory(&context, sm2_signature_len);
    if (sm2_shared_buf == NULL) {
        printf("Malloc sm2 shared memory failed.\n");
        goto error;
    }

    res = enclave_sm2_sign(&context, &retval, sm3_hash_for_sm2, sizeof(sm3_hash_for_sm2), (uint8_t*)sm2_shared_buf, &sm2_signature_len);
     if (res != CC_SUCCESS || retval != 0) {
        printf("Enclave SM2 sign failed.\n");
    } else {
        printf("SM2 Signature (len=%zu): ", sm2_signature_len);
        for (int i = 0; i < sm2_signature_len; i++) {
            printf("%02x", (unsigned char)sm2_shared_buf[i]);
        }
        printf("\n");
    }
    cc_free_shared_memory(&context, sm2_shared_buf);

    printf("--- Tongsuo crypto tests finished ---\n\n");

    res = cc_free_shared_memory(&context, shared_buf);
    if (res != CC_SUCCESS) {
        printf("Free shared memory failed:%x.\n", res);
    }

error:
    res = cc_enclave_destroy(&context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
end:
    return res;
}

