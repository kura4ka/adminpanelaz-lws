#include "telegram_auth.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>

enum {
    FIELD_LIMIT = 64, KEY_LIMIT = 64, TOKEN_LIMIT = 256,
    SHA256_SIZE = TELEGRAM_AUTH_PROOF_SIZE, JSON_DEPTH_LIMIT = 16
};

struct form_field {
    const char *key;
    const char *value;
};

static int hex_digit(unsigned char byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    return -1;
}

static bool digit(unsigned char byte)
{
    return byte >= '0' && byte <= '9';
}

static bool form_key_byte(unsigned char byte)
{
    return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || digit(byte) || byte == '_';
}

static bool form_decode(char *text, bool key)
{
    char *output = text;
    for (const char *p = text; *p; ++p) {
        unsigned char byte = (unsigned char)*p;
        if (byte == '%') {
            if (!p[1] || !p[2])
                return false;
            int high = hex_digit((unsigned char)p[1]);
            int low = hex_digit((unsigned char)p[2]);
            if (high < 0 || low < 0)
                return false;
            byte = (unsigned char)((high << 4) | low);
            p += 2;
        } else if (byte == '+') {
            byte = ' ';
        }

        /*
         * A line break inside a field would make the newline-delimited signed
         * representation ambiguous. Telegram's user JSON uses escaped text.
         */
        if (byte < ' ' || byte == 127 || (key && !form_key_byte(byte)))
            return false;
        *output++ = (char)byte;
    }
    *output = '\0';
    return !key || (output != text && output - text <= KEY_LIMIT);
}

static int compare_fields(const void *left, const void *right)
{
    const struct form_field *a = left;
    const struct form_field *b = right;
    return strcmp(a->key, b->key);
}

static size_t parse_form(char *text, struct form_field fields[FIELD_LIMIT])
{
    size_t count = 0;
    char *field = text;
    while (field) {
        char *next = strchr(field, '&');
        if (next)
            *next++ = '\0';
        char *separator = strchr(field, '=');
        if (!separator || count == FIELD_LIMIT)
            return 0;
        *separator = '\0';
        if (!form_decode(field, true) || !form_decode(separator + 1, false))
            return 0;
        fields[count++] = (struct form_field){ .key = field, .value = separator + 1 };
        field = next;
    }

    qsort(fields, count, sizeof(*fields), compare_fields);
    for (size_t i = 1; i < count; ++i)
        if (!strcmp(fields[i - 1].key, fields[i].key))
            return 0;
    return count;
}

static bool positive_integer(const char *text, size_t length, uint64_t *number)
{
    if (!length || length > 19)
        return false;
    uint64_t value = 0;
    for (size_t i = 0; i < length; ++i) {
        if (!digit((unsigned char)text[i]))
            return false;
        unsigned int next = (unsigned int)(text[i] - '0');
        if (value > (INT64_MAX - next) / UINT64_C(10))
            return false;
        value = value * 10 + next;
    }
    if (!value)
        return false;
    *number = value;
    return true;
}

static const char *trim_spaces(const char *text, size_t *length)
{
    while (*text == ' ')
        ++text;
    *length = strlen(text);
    while (*length && text[*length - 1] == ' ')
        --*length;
    return text;
}

static bool fresh_auth_date(const char *text, uint64_t now, unsigned int max_age,
                            unsigned int skew, uint64_t *auth_date)
{
    size_t length;
    text = trim_spaces(text, &length);
    if (!positive_integer(text, length, auth_date))
        return false;

    if (max_age < TELEGRAM_AUTH_MIN_TTL)
        max_age = TELEGRAM_AUTH_MIN_TTL;
    if (max_age > TELEGRAM_AUTH_MAX_TTL)
        max_age = TELEGRAM_AUTH_MAX_TTL;
    if (skew > max_age)
        skew = max_age;
    return *auth_date <= now ? now - *auth_date <= max_age : *auth_date - now <= skew;
}

static bool decode_hash(const char *text, bool mini, unsigned char hash[SHA256_SIZE])
{
    size_t length;
    if (mini)
        length = strlen(text);
    else
        text = trim_spaces(text, &length);
    if (length != SHA256_SIZE * 2)
        return false;

    for (size_t i = 0; i < SHA256_SIZE; ++i) {
        unsigned char first = (unsigned char)text[i * 2];
        unsigned char second = (unsigned char)text[i * 2 + 1];
        if (mini && ((first >= 'A' && first <= 'F') || (second >= 'A' && second <= 'F')))
            return false;
        int high = hex_digit(first);
        int low = hex_digit(second);
        if (high < 0 || low < 0)
            return false;
        hash[i] = (unsigned char)((high << 4) | low);
    }
    return true;
}

static void skip_json_space(const char **cursor)
{
    const char *p = *cursor;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        ++p;
    *cursor = p;
}

static bool json_string(const char **cursor, bool *is_id)
{
    const char *p = *cursor;
    if (*p++ != '"')
        return false;

    size_t count = 0;
    bool matches = true;
    while (*p && *p != '"') {
        unsigned int code = (unsigned char)*p++;
        if (code < ' ')
            return false;
        if (code == '\\') {
            if (!*p)
                return false;
            code = (unsigned char)*p++;
            if (code == 'u') {
                code = 0;
                for (int i = 0; i < 4; ++i) {
                    int digit_value = hex_digit((unsigned char)*p);
                    if (digit_value < 0)
                        return false;
                    ++p;
                    code = (code << 4) | (unsigned int)digit_value;
                }
            } else if (!strchr("\"\\/bfnrt", (int)code)) {
                return false;
            }
        }
        if (count >= 2 || code != (unsigned char)"id"[count])
            matches = false;
        ++count;
    }
    if (*p != '"')
        return false;
    *cursor = p + 1;
    if (is_id)
        *is_id = matches && count == 2;
    return true;
}

static bool json_number(const char **cursor)
{
    const char *p = *cursor;
    if (*p == '-')
        ++p;
    if (!digit((unsigned char)*p))
        return false;
    if (*p++ != '0')
        while (digit((unsigned char)*p))
            ++p;
    if (*p == '.') {
        if (!digit((unsigned char)*++p))
            return false;
        while (digit((unsigned char)*p))
            ++p;
    }
    if (*p == 'e' || *p == 'E') {
        ++p;
        if (*p == '+' || *p == '-')
            ++p;
        if (!digit((unsigned char)*p))
            return false;
        while (digit((unsigned char)*p))
            ++p;
    }
    *cursor = p;
    return true;
}

static bool json_value(const char **cursor, unsigned int depth)
{
    if (depth >= JSON_DEPTH_LIMIT)
        return false;
    skip_json_space(cursor);
    const char *p = *cursor;
    if (*p == '"')
        return json_string(cursor, NULL);
    if (*p == '-' || digit((unsigned char)*p))
        return json_number(cursor);

    const char *literal = *p == 't' ? "true" : *p == 'f' ? "false" : *p == 'n' ? "null" : NULL;
    if (literal) {
        size_t length = strlen(literal);
        if (strncmp(p, literal, length))
            return false;
        *cursor = p + length;
        return true;
    }

    bool object = *p == '{';
    if (!object && *p != '[')
        return false;
    char end = object ? '}' : ']';
    ++p;
    skip_json_space(&p);
    if (*p != end) {
        for (;;) {
            if (object) {
                if (!json_string(&p, NULL))
                    return false;
                skip_json_space(&p);
                if (*p++ != ':')
                    return false;
            }
            if (!json_value(&p, depth + 1))
                return false;
            skip_json_space(&p);
            if (*p != ',')
                break;
            ++p;
            skip_json_space(&p);
        }
    }
    if (*p != end)
        return false;
    *cursor = p + 1;
    return true;
}

static bool mini_user_id(const char *p, uint64_t *id)
{
    skip_json_space(&p);
    if (*p++ != '{')
        return false;
    skip_json_space(&p);

    bool found = false;
    while (*p != '}') {
        bool key_is_id;
        if (!json_string(&p, &key_is_id))
            return false;
        skip_json_space(&p);
        if (*p++ != ':')
            return false;
        skip_json_space(&p);
        if (key_is_id) {
            if (found)
                return false;
            const char *begin = p;
            if (!json_number(&p) || !positive_integer(begin, (size_t)(p - begin), id))
                return false;
            found = true;
        } else if (!json_value(&p, 1)) {
            return false;
        }
        skip_json_space(&p);
        if (*p != ',')
            break;
        ++p;
        skip_json_space(&p);
        if (*p == '}')
            return false;
    }
    if (!found || *p++ != '}')
        return false;
    skip_json_space(&p);
    return !*p;
}

static bool verify_signature(const char *bot_token, size_t token_length, const char *canonical,
                             size_t size, bool mini, const unsigned char expected[SHA256_SIZE])
{
    unsigned char secret[SHA256_SIZE];
    unsigned char digest[SHA256_SIZE];
    unsigned int length = 0;
    const EVP_MD *algorithm = EVP_sha256();
    const char context[] = "WebAppData";
    bool derived = mini
        ? HMAC(algorithm, context, sizeof(context) - 1, (const unsigned char *)bot_token,
               token_length, secret, &length) != NULL
        : EVP_Digest(bot_token, token_length, secret, &length, algorithm, NULL) == 1;
    bool valid = derived && length == sizeof(secret) &&
        HMAC(algorithm, secret, sizeof(secret), (const unsigned char *)canonical, size,
             digest, &length) && length == sizeof(digest) &&
        CRYPTO_memcmp(digest, expected, sizeof(digest)) == 0;
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(digest, sizeof(digest));
    return valid;
}

static bool verify(const char *data, size_t size, const char *bot_token,
                   uint64_t now, unsigned int max_age, unsigned int future_skew,
                   struct telegram_auth_identity *identity, bool mini)
{
    if (!identity)
        return false;
    *identity = (struct telegram_auth_identity){0};
    if (!bot_token || !data || !size || size > TELEGRAM_AUTH_DATA_MAX || memchr(data, '\0', size))
        return false;

    size_t token_length = 0;
    while (token_length <= TOKEN_LIMIT && bot_token[token_length])
        ++token_length;
    if (!token_length || token_length > TOKEN_LIMIT)
        return false;

    /* Form decoding never expands the input. Each signed pair retains at
     * most its original length, including the separator to the next field. */
    char *storage = OPENSSL_malloc((size + 1) * 2);
    if (!storage)
        return false;
    memcpy(storage, data, size);
    storage[size] = '\0';
    char *canonical = storage + size + 1;
    struct form_field fields[FIELD_LIMIT];
    size_t count = parse_form(storage, fields);
    const char *hash = NULL;
    const char *date = NULL;
    const char *user = NULL;
    const char *identity_key = mini ? "user" : "id";
    size_t written = 0;

    for (size_t i = 0; i < count; ++i) {
        const struct form_field *field = &fields[i];
        if (!strcmp(field->key, "hash")) {
            hash = field->value;
            continue;
        }
        if (!strcmp(field->key, "auth_date"))
            date = field->value;
        if (!strcmp(field->key, identity_key))
            user = field->value;

        if (written)
            canonical[written++] = '\n';
        size_t key_length = strlen(field->key);
        memcpy(canonical + written, field->key, key_length);
        written += key_length;
        canonical[written++] = '=';
        size_t value_length = strlen(field->value);
        memcpy(canonical + written, field->value, value_length);
        written += value_length;
    }

    unsigned char expected[SHA256_SIZE];
    struct telegram_auth_identity verified = {0};
    bool valid = hash && date && user && decode_hash(hash, mini, expected) &&
        fresh_auth_date(date, now, max_age, future_skew, &verified.auth_date) &&
        verify_signature(bot_token, token_length, canonical, written, mini, expected);
    if (valid) {
        if (mini) {
            valid = mini_user_id(user, &verified.user_id);
        } else {
            size_t length;
            user = trim_spaces(user, &length);
            valid = positive_integer(user, length, &verified.user_id);
        }
    }
    if (valid) {
        memcpy(verified.proof, expected, sizeof(verified.proof));
        *identity = verified;
    }
    OPENSSL_clear_free(storage, (size + 1) * 2);
    return valid;
}

bool telegram_auth_verify_widget(const char *data, size_t size, const char *bot_token,
                                uint64_t now, unsigned int max_age, unsigned int future_skew,
                                struct telegram_auth_identity *identity)
{
    return verify(data, size, bot_token, now, max_age, future_skew, identity, false);
}

bool telegram_auth_verify_init_data(const char *data, size_t size, const char *bot_token,
                                   uint64_t now, unsigned int max_age, unsigned int future_skew,
                                   struct telegram_auth_identity *identity)
{
    return verify(data, size, bot_token, now, max_age, future_skew, identity, true);
}
