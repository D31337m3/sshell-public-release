/*
 * test_multiuser.c - Feature-lock tests for multiuser token/session logic.
 */

#include "../c-src/common/multiuser.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_init_and_defaults(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);
    assert(mu.sharing_enabled == false);
    assert(mu.share_token[0] == '\0');
    assert(multiuser_get_user_count(&mu) == 0);
}

static void test_enable_sharing_generates_token(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);
    assert(mu.sharing_enabled == true);
    /* Token must be exactly TOKEN_LENGTH characters. */
    assert((int)strlen(token) == TOKEN_LENGTH);
    /* Token must only contain alphanumeric characters [a-zA-Z0-9]. */
    for (int i = 0; i < TOKEN_LENGTH; i++) {
        char c = token[i];
        assert((c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'z') ||
               (c >= 'A' && c <= 'Z'));
    }
}

static void test_validate_token_correct(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);

    /* Validate the just-generated token — must succeed. */
    assert(multiuser_validate_token(&mu, token) == true);
}

static void test_validate_token_wrong(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);

    /* Wrong token must be rejected. */
    char bad_token[TOKEN_LENGTH + 1];
    memset(bad_token, 'x', TOKEN_LENGTH);
    bad_token[TOKEN_LENGTH] = '\0';
    assert(multiuser_validate_token(&mu, bad_token) == false);
}

static void test_validate_token_disabled(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);

    /* Disable sharing — token should no longer be valid. */
    multiuser_disable_sharing(&mu);
    assert(mu.sharing_enabled == false);
    assert(multiuser_validate_token(&mu, token) == false);
}

static void test_add_remove_user(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);

    /* Use fd=5 as a fake connected socket. */
    int fake_fd = 5;
    assert(multiuser_add_user(&mu, fake_fd, "guest", ACCESS_READ_ONLY, true) == 0);
    assert(multiuser_get_user_count(&mu) == 1);
    assert(multiuser_has_write_access(&mu, fake_fd) == false);

    multiuser_remove_user(&mu, fake_fd);
    assert(multiuser_get_user_count(&mu) == 0);
}

static void test_add_user_with_write_access(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token, TOKEN_LENGTH + 1) == 0);

    int fake_fd = 7;
    assert(multiuser_add_user(&mu, fake_fd, "collab", ACCESS_READ_WRITE, false) == 0);
    assert(multiuser_has_write_access(&mu, fake_fd) == true);

    multiuser_remove_user(&mu, fake_fd);
    assert(multiuser_get_user_count(&mu) == 0);
}

static void test_tokens_differ_across_enables(void) {
    multiuser_session_t mu;
    assert(multiuser_init(&mu) == 0);

    char token1[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token1, TOKEN_LENGTH + 1) == 0);
    multiuser_disable_sharing(&mu);

    char token2[TOKEN_LENGTH + 1] = {0};
    assert(multiuser_enable_sharing(&mu, token2, TOKEN_LENGTH + 1) == 0);

    /* Tokens generated in separate enable calls must differ. */
    assert(strcmp(token1, token2) != 0);
}

int main(void) {
    printf("Running multiuser tests...\n");
    test_init_and_defaults();
    test_enable_sharing_generates_token();
    test_validate_token_correct();
    test_validate_token_wrong();
    test_validate_token_disabled();
    test_add_remove_user();
    test_add_user_with_write_access();
    test_tokens_differ_across_enables();
    printf("OK: multiuser tests passed\n");
    return 0;
}
