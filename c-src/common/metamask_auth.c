/*
 * metamask_auth.c - MetaMask authentication implementation
 *
 * Implements Ethereum personal_sign style verification:
 *   hash = keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
 *   recover pubkey from (r,s,v)
 *   address = last20(keccak256(pubkey[1:]))
 */

#include "metamask_auth.h"
#include "logger.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <secp256k1.h>
#include <secp256k1_recovery.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    if (!hex || !out) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

static void bytes_to_lower_hex(const unsigned char *bytes, size_t len, char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    if (!bytes || !out || out_len < (len * 2 + 1)) {
        return;
    }

    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static bool keccak256(const unsigned char *data, size_t data_len, unsigned char out32[32]) {
    bool ok = false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    static OSSL_PROVIDER *legacy_provider = NULL;
    if (!legacy_provider) {
        legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    }
    EVP_MD *md = EVP_MD_fetch(NULL, "KECCAK-256", NULL);
    const EVP_MD *md_fallback = NULL;
    if (!md) {
        md_fallback = EVP_get_digestbyname("KECCAK-256");
    }
    if (!md && !md_fallback) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
#else
    const EVP_MD *md_fallback = EVP_get_digestbyname("KECCAK-256");
    if (!md_fallback) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
#endif

    if (EVP_DigestInit_ex(ctx,
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                          md ? md :
#endif
                          md_fallback,
                          NULL) != 1) {
        goto done;
    }
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        goto done;
    }

    unsigned int out_len = 0;
    if (EVP_DigestFinal_ex(ctx, out32, &out_len) != 1 || out_len != 32) {
        goto done;
    }

    ok = true;

done:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (md) EVP_MD_free(md);
#endif
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool eth_personal_sign_hash(const char *message, unsigned char out32[32]) {
    if (!message) return false;
    size_t msg_len = strlen(message);

    char prefix[128];
    int prefix_len = snprintf(prefix,
                              sizeof(prefix),
                              "\x19" "Ethereum Signed Message:\n%zu",
                              msg_len);
    if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) {
        return false;
    }

    size_t total_len = (size_t)prefix_len + msg_len;
    unsigned char *buf = (unsigned char *)malloc(total_len);
    if (!buf) return false;
    memcpy(buf, prefix, (size_t)prefix_len);
    memcpy(buf + (size_t)prefix_len, message, msg_len);

    bool ok = keccak256(buf, total_len, out32);
    free(buf);
    return ok;
}

static bool recover_address_from_signature(const char *message, const char *signature, unsigned char out20[20]) {
    if (!message || !signature) return false;
    if (strlen(signature) != 132 || strncmp(signature, "0x", 2) != 0) return false;

    unsigned char sig65[65];
    if (!hex_to_bytes(signature + 2, sig65, sizeof(sig65))) {
        return false;
    }

    int v = sig65[64];
    int recid = v;
    if (recid >= 27) {
        recid -= 27;
    }
    if (recid < 0 || recid > 3) {
        return false;
    }

    unsigned char msg_hash[32];
    if (!eth_personal_sign_hash(message, msg_hash)) {
        return false;
    }

    secp256k1_context *secp = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (!secp) {
        return false;
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp, &sig, sig65, recid)) {
        secp256k1_context_destroy(secp);
        return false;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ecdsa_recover(secp, &pubkey, &sig, msg_hash)) {
        secp256k1_context_destroy(secp);
        return false;
    }

    unsigned char pubkey_ser[65];
    size_t pubkey_ser_len = sizeof(pubkey_ser);
    if (!secp256k1_ec_pubkey_serialize(secp,
                                       pubkey_ser,
                                       &pubkey_ser_len,
                                       &pubkey,
                                       SECP256K1_EC_UNCOMPRESSED) ||
        pubkey_ser_len != 65) {
        secp256k1_context_destroy(secp);
        return false;
    }

    secp256k1_context_destroy(secp);

    unsigned char pub_hash[32];
    if (!keccak256(pubkey_ser + 1, 64, pub_hash)) {
        return false;
    }

    memcpy(out20, pub_hash + 12, 20);
    return true;
}

/* 
 * Simplified verification - checks signature format only
 * TODO: Implement full ECDSA verification with secp256k1
 */
bool metamask_verify_signature(const char *address, const char *message,
                               const char *signature) {
    if (!address || !message || !signature) {
        log_warn("Invalid auth parameters");
        return false;
    }

    if (strlen(address) != 42 || strncmp(address, "0x", 2) != 0) {
        log_warn("Invalid Ethereum address format");
        return false;
    }

    unsigned char expected20[20];
    if (!hex_to_bytes(address + 2, expected20, sizeof(expected20))) {
        log_warn("Invalid Ethereum address hex");
        return false;
    }

    unsigned char recovered20[20];
    if (!recover_address_from_signature(message, signature, recovered20)) {
        log_warn("Signature recovery failed");
        return false;
    }

    if (memcmp(expected20, recovered20, 20) != 0) {
        char expected_hex[41];
        char recovered_hex[41];
        bytes_to_lower_hex(expected20, 20, expected_hex, sizeof(expected_hex));
        bytes_to_lower_hex(recovered20, 20, recovered_hex, sizeof(recovered_hex));
        log_warn("Signature does not match address: expected=0x%s recovered=0x%s", expected_hex, recovered_hex);
        return false;
    }

    return true;
}

bool metamask_recover_address(const char *message, const char *signature,
                              char *address_out) {
    if (!message || !signature || !address_out) {
        return false;
    }

    unsigned char recovered20[20];
    if (!recover_address_from_signature(message, signature, recovered20)) {
        return false;
    }

    char hex[41];
    bytes_to_lower_hex(recovered20, 20, hex, sizeof(hex));
    snprintf(address_out, 43, "0x%s", hex);
    return true;
}
