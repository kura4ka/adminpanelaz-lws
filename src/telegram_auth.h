#ifndef TELEGRAM_AUTH_H
#define TELEGRAM_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    TELEGRAM_AUTH_DATA_MAX = 8192,
    TELEGRAM_AUTH_PROOF_SIZE = 32,
    TELEGRAM_AUTH_DEFAULT_TTL = 300,
    TELEGRAM_AUTH_MIN_TTL = 30,
    TELEGRAM_AUTH_MAX_TTL = 86400
};

struct telegram_auth_identity {
    uint64_t user_id;
    uint64_t auth_date;
    /* Verified HMAC bytes, identical for equivalent form encodings. */
    unsigned char proof[TELEGRAM_AUTH_PROOF_SIZE];
};

/*
 * data is the raw URL-encoded query or initData, without the leading '?'.
 * now, max_age and future_skew are in seconds. max_age is clamped to the
 * upstream range, and future_skew cannot exceed that age. On failure
 * identity is zeroed. Account lookup, replay policy and sessions belong
 * to the caller.
 */
bool telegram_auth_verify_widget(const char *data, size_t size, const char *bot_token,
                                uint64_t now, unsigned int max_age, unsigned int future_skew,
                                struct telegram_auth_identity *identity);
bool telegram_auth_verify_init_data(const char *data, size_t size, const char *bot_token,
                                   uint64_t now, unsigned int max_age, unsigned int future_skew,
                                   struct telegram_auth_identity *identity);

#endif
