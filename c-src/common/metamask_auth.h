/*
 * metamask_auth.h - Ethereum signature verification for MetaMask authentication
 */

#ifndef SSHELL_METAMASK_AUTH_H
#define SSHELL_METAMASK_AUTH_H

#include <stdbool.h>

/* Verify Ethereum signature */
bool metamask_verify_signature(const char *address, const char *message,
                               const char *signature);

/* Extract address from signature (signature recovery) */
bool metamask_recover_address(const char *message, const char *signature,
                              char *address_out);

#endif /* SSHELL_METAMASK_AUTH_H */
