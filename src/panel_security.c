#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_security.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <zlib.h>

#include <stddef.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_pton InetPtonA
#define inet_ntop InetNtopA
#else
#include <arpa/inet.h>
#endif

enum {
    RULES_MAX = 64, LOGIN_SLOTS = 512, FAILURE_LIMIT = 10, FAILURE_WINDOW = 300,
    CAPTCHA_THRESHOLD = 3, CAPTCHA_SLOTS = 128, CAPTCHA_IP_LIMIT = 4, CAPTCHA_SECONDS = 300,
    CAPTCHA_ID_BYTES = 16, CAPTCHA_DIGEST_BYTES = 32, CAPTCHA_TEXT_SIZE = 6,
    IMAGE_WIDTH = 132, IMAGE_HEIGHT = 45, IMAGE_ROW = IMAGE_WIDTH / 2 + 1,
    IMAGE_RAW_SIZE = IMAGE_HEIGHT * IMAGE_ROW
};

struct ip_address {
    uint8_t bytes[16];
    uint8_t size;
};

struct ip_rule {
    struct ip_address address;
    unsigned int prefix;
};

struct ip_rules {
    struct ip_rule entries[RULES_MAX];
    size_t count;
};

struct login_attempts {
    struct ip_address address;
    unsigned int count;
    uint64_t failure_times[FAILURE_LIMIT];
};

struct captcha {
    struct ip_address address;
    unsigned char id[CAPTCHA_ID_BYTES];
    unsigned char digest[CAPTCHA_DIGEST_BYTES];
    uint64_t deadline;
};

static struct ip_rules allowlist;
static struct ip_rules trusted_proxies;
static struct login_attempts login_attempts[LOGIN_SLOTS];
static struct captcha captchas[CAPTCHA_SLOTS];
static unsigned char captcha_key[CAPTCHA_DIGEST_BYTES];
static bool has_captcha_key;

static bool parse_address(const char *value, struct ip_address *address)
{
    static const uint8_t mapped_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (!value)
        return false;
    if (inet_pton(AF_INET, value, address->bytes) == 1) {
        address->size = 4;
        return true;
    }
    if (inet_pton(AF_INET6, value, address->bytes) != 1)
        return false;
    address->size = 16;
    if (memcmp(address->bytes, mapped_prefix, sizeof(mapped_prefix)) == 0) {
        memmove(address->bytes, address->bytes + sizeof(mapped_prefix), 4);
        address->size = 4;
    }
    return true;
}

static bool trim_copy(const char *begin, const char *end, char *out, size_t capacity)
{
    while (begin < end && (*begin == ' ' || *begin == '\t'))
        ++begin;
    while (begin < end && (end[-1] == ' ' || end[-1] == '\t'))
        --end;
    size_t length = (size_t)(end - begin);
    if (!length || length >= capacity)
        return false;
    memcpy(out, begin, length);
    out[length] = '\0';
    return true;
}

static bool parse_rule(char *value, bool exact, struct ip_rule *rule)
{
    char *slash = strchr(value, '/');
    if (slash) {
        if (exact)
            return false;
        *slash++ = '\0';
    }
    if (!parse_address(value, &rule->address))
        return false;
    bool mapped = rule->address.size == 4 && strchr(value, ':') != NULL;
    unsigned int max_prefix = mapped ? 128 : rule->address.size * 8U;
    unsigned int prefix = max_prefix;
    if (slash) {
        if (!*slash)
            return false;
        prefix = 0;
        for (; *slash; ++slash) {
            if (*slash < '0' || *slash > '9')
                return false;
            prefix = prefix * 10U + (unsigned int)(*slash - '0');
            if (prefix > max_prefix)
                return false;
        }
        if (mapped && prefix < 96)
            return false;
    }
    rule->prefix = mapped ? prefix - 96 : prefix;
    return true;
}

static bool parse_rules(const char *list, bool exact, struct ip_rules *rules)
{
    rules->count = 0;
    if (!list || !*list)
        return true;
    const char *end = list + strlen(list);
    while (true) {
        const char *comma = strchr(list, ',');
        char value[PANEL_SECURITY_IP_SIZE + 4];
        if (rules->count == RULES_MAX || !trim_copy(list, comma ? comma : end, value, sizeof(value)) ||
            !parse_rule(value, exact, &rules->entries[rules->count]))
            return false;
        ++rules->count;
        if (!comma)
            return true;
        list = comma + 1;
    }
}

static bool matches(const struct ip_address *address, const struct ip_rule *rule)
{
    if (address->size != rule->address.size)
        return false;
    unsigned int bytes = rule->prefix / 8;
    unsigned int remainder = rule->prefix % 8;
    if (memcmp(address->bytes, rule->address.bytes, bytes) != 0)
        return false;
    if (!remainder)
        return true;
    unsigned int mask = 0xffU << (8 - remainder);
    return ((address->bytes[bytes] ^ rule->address.bytes[bytes]) & mask) == 0;
}

static bool any_match(const struct ip_address *address, const struct ip_rules *rules)
{
    for (size_t i = 0; i < rules->count; ++i) {
        if (matches(address, &rules->entries[i]))
            return true;
    }
    return false;
}

static bool same_address(const struct ip_address *left, const struct ip_address *right)
{
    return left->size == right->size && memcmp(left->bytes, right->bytes, left->size) == 0;
}

bool panel_security_configure(const char *allowed, const char *proxies)
{
    struct ip_rules new_allowed = {0};
    struct ip_rules new_proxies = {0};
    if (!parse_rules(allowed, false, &new_allowed) || !parse_rules(proxies, true, &new_proxies))
        return false;
    allowlist = new_allowed;
    trusted_proxies = new_proxies;
    return true;
}

bool panel_security_client_ip(const char *peer, const char *forwarded_for, char out[PANEL_SECURITY_IP_SIZE])
{
    struct ip_address address = {0};
    if (!out)
        return false;
    out[0] = '\0';
    if (!parse_address(peer, &address))
        return false;
    if (forwarded_for && *forwarded_for && any_match(&address, &trusted_proxies)) {
        size_t length = strlen(forwarded_for);
        if (length > PANEL_SECURITY_FORWARDED_MAX)
            return false;
        const char *end = forwarded_for + length;
        while (end > forwarded_for) {
            const char *begin = end;
            while (begin > forwarded_for && begin[-1] != ',')
                --begin;
            char value[PANEL_SECURITY_IP_SIZE];
            if (!trim_copy(begin, end, value, sizeof(value)) || !parse_address(value, &address))
                return false;
            if (begin == forwarded_for || !any_match(&address, &trusted_proxies))
                break;
            end = begin - 1;
            if (end == forwarded_for)
                return false;
        }
    }
    return inet_ntop(address.size == 4 ? AF_INET : AF_INET6, address.bytes, out, PANEL_SECURITY_IP_SIZE) != NULL;
}

bool panel_security_ip_allowed(const char *ip)
{
    struct ip_address address = {0};
    return parse_address(ip, &address) && (!allowlist.count || any_match(&address, &allowlist));
}

static uint64_t monotonic_seconds(void)
{
#ifdef _WIN32
    return GetTickCount64() / 1000 + 1;
#else
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec >= 0 ? (uint64_t)now.tv_sec + 1 : 0;
#endif
}

static void prune_failures(struct login_attempts *attempts, uint64_t now)
{
    unsigned int expired = 0;
    while (expired < attempts->count && now >= attempts->failure_times[expired] &&
           now - attempts->failure_times[expired] >= FAILURE_WINDOW)
        ++expired;
    attempts->count -= expired;
    if (expired)
        memmove(attempts->failure_times, attempts->failure_times + expired,
                attempts->count * sizeof(attempts->failure_times[0]));
}

static struct login_attempts *find_attempts(const struct ip_address *address, uint64_t now, bool create)
{
    struct login_attempts *empty = NULL;
    for (size_t i = 0; i < LOGIN_SLOTS; ++i) {
        struct login_attempts *attempts = &login_attempts[i];
        prune_failures(attempts, now);
        if (!attempts->count) {
            if (!empty)
                empty = attempts;
        } else if (same_address(address, &attempts->address)) {
            return attempts;
        }
    }
    if (empty && create)
        empty->address = *address;
    return empty;
}

unsigned int panel_security_retry_after(const char *ip)
{
    struct ip_address address = {0};
    uint64_t now = monotonic_seconds();
    if (!now || !parse_address(ip, &address))
        return FAILURE_WINDOW;
    struct login_attempts *attempts = find_attempts(&address, now, false);
    if (!attempts)
        return FAILURE_WINDOW;
    if (attempts->count < FAILURE_LIMIT)
        return 0;
    uint64_t elapsed = now >= attempts->failure_times[0] ? now - attempts->failure_times[0] : 0;
    return (unsigned int)(FAILURE_WINDOW - elapsed);
}

void panel_security_record_login(const char *ip, bool success)
{
    struct ip_address address = {0};
    uint64_t now = monotonic_seconds();
    if (!now || !parse_address(ip, &address))
        return;
    struct login_attempts *attempts = find_attempts(&address, now, !success);
    if (!attempts)
        return;
    if (success) {
        attempts->count = 0;
        for (size_t i = 0; i < CAPTCHA_SLOTS; ++i) {
            if (same_address(&captchas[i].address, &address))
                captchas[i].deadline = 0;
        }
    } else if (attempts->count < FAILURE_LIMIT) {
        attempts->failure_times[attempts->count++] = now;
    }
}

bool panel_security_login_needs_captcha(const char *ip)
{
    struct ip_address address = {0};
    uint64_t now = monotonic_seconds();
    if (!now || !parse_address(ip, &address))
        return false;
    struct login_attempts *attempts = find_attempts(&address, now, false);
    return attempts && attempts->count >= CAPTCHA_THRESHOLD;
}

static unsigned int noise(uint32_t *state, unsigned int limit)
{
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state % limit;
}

static void plot(unsigned char *pixels, int x, int y, unsigned int shade)
{
    if (x < 0 || x >= IMAGE_WIDTH || y < 0 || y >= IMAGE_HEIGHT)
        return;
    unsigned int shift = x % 2 ? 0 : 4;
    unsigned char *pair = pixels + y * IMAGE_ROW + 1 + x / 2;
    *pair = (unsigned char)((*pair & ~(15U << shift)) | (shade << shift));
}

static void draw_challenge(unsigned char pixels[IMAGE_RAW_SIZE], const unsigned char *selection, uint32_t seed)
{
    /* Five by seven glyphs for ABCDEFGHJKLMNPQRSTUVWXYZ23456789. */
    static const unsigned char glyphs[][7] = {
        {14, 17, 17, 31, 17, 17, 17}, {30, 17, 17, 30, 17, 17, 30},
        {14, 17, 16, 16, 16, 17, 14}, {30, 17, 17, 17, 17, 17, 30},
        {31, 16, 16, 30, 16, 16, 31}, {31, 16, 16, 30, 16, 16, 16},
        {14, 17, 16, 23, 17, 17, 15}, {17, 17, 17, 31, 17, 17, 17},
        { 7,  2,  2,  2, 18, 18, 12}, {17, 18, 20, 24, 20, 18, 17},
        {16, 16, 16, 16, 16, 16, 31}, {17, 27, 21, 21, 17, 17, 17},
        {17, 25, 21, 19, 17, 17, 17}, {30, 17, 17, 30, 16, 16, 16},
        {14, 17, 17, 17, 21, 18, 13}, {30, 17, 17, 30, 20, 18, 17},
        {15, 16, 16, 14,  1,  1, 30}, {31,  4,  4,  4,  4,  4,  4},
        {17, 17, 17, 17, 17, 17, 14}, {17, 17, 17, 17, 17, 10,  4},
        {17, 17, 17, 21, 21, 21, 10}, {17, 17, 10,  4, 10, 17, 17},
        {17, 17, 10,  4,  4,  4,  4}, {31,  1,  2,  4,  8, 16, 31},
        {14, 17,  1,  2,  4,  8, 31}, {30,  1,  1, 14,  1,  1, 30},
        { 2,  6, 10, 18, 31,  2,  2}, {31, 16, 16, 30,  1,  1, 30},
        { 6,  8, 16, 30, 17, 17, 14}, {31,  1,  2,  4,  8,  8,  8},
        {14, 17, 17, 14, 17, 17, 14}, {14, 17, 17, 15,  1,  2, 12}
    };
    if (!seed)
        seed = 1;
    for (int row = 0; row < IMAGE_HEIGHT; ++row) {
        pixels[row * IMAGE_ROW] = 0;
        memset(pixels + row * IMAGE_ROW + 1, 0xff, IMAGE_ROW - 1);
    }
    for (int n = 0; n < 3; ++n) {
        int y = 6 + (int)noise(&seed, IMAGE_HEIGHT - 12);
        int direction = noise(&seed, 2) ? 1 : -1;
        for (int x = 0; x < IMAGE_WIDTH; ++x) {
            plot(pixels, x, y, 6 + noise(&seed, 6));
            if (noise(&seed, 3) == 0)
                y += direction;
            if (y < 2 || y > IMAGE_HEIGHT - 3 || noise(&seed, 8) == 0)
                direction = -direction;
        }
    }
    for (int i = 0; i < CAPTCHA_TEXT_SIZE; ++i) {
        int origin_x = 5 + 21 * i + (int)noise(&seed, 5);
        int origin_y = 7 + (int)noise(&seed, 10);
        int tilt = (int)noise(&seed, 9) - 4;
        int step = 3 + (int)noise(&seed, 2);
        for (int row = 0; row < 7 * step; ++row) {
            int x = origin_x + (row - 3 * step) * tilt / (4 * step);
            unsigned int mask = glyphs[selection[i]][row / step];
            for (int column = 0; column < 15; ++column) {
                if (mask & (16U >> (column / 3)))
                    plot(pixels, x + column, origin_y + row, noise(&seed, 4));
            }
        }
    }
    for (int i = 0; i < 260; ++i) {
        int x = (int)noise(&seed, IMAGE_WIDTH);
        int y = (int)noise(&seed, IMAGE_HEIGHT);
        unsigned int shade = 2 + noise(&seed, 14);
        plot(pixels, x, y, shade);
    }
}

static void write_be32(unsigned char out[4], uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static size_t write_chunk(unsigned char *out, const char type[5], const unsigned char *payload, size_t size)
{
    write_be32(out, (uint32_t)size);
    memcpy(out + 4, type, 4);
    if (size)
        memcpy(out + 8, payload, size);
    uLong checksum = crc32(0, out + 4, (uInt)(size + 4));
    write_be32(out + 8 + size, (uint32_t)checksum);
    return 12 + size;
}

static bool challenge_png(const unsigned char selection[CAPTCHA_TEXT_SIZE], uint32_t seed,
                          unsigned char *png, size_t capacity, size_t *written)
{
    static const unsigned char signature[] = {137, 80, 78, 71, 13, 10, 26, 10};
    unsigned char pixels[IMAGE_RAW_SIZE];
    unsigned char compressed[IMAGE_RAW_SIZE + 64];
    unsigned char header[13] = {0};
    draw_challenge(pixels, selection, seed);
    uLongf compressed_size = sizeof(compressed);
    if (compress2(compressed, &compressed_size, pixels, sizeof(pixels), 2) != Z_OK ||
        capacity < sizeof(signature) + sizeof(header) + compressed_size + 36)
        return false;
    write_be32(header, IMAGE_WIDTH);
    write_be32(header + 4, IMAGE_HEIGHT);
    header[8] = 4;
    memcpy(png, signature, sizeof(signature));
    size_t offset = sizeof(signature);
    offset += write_chunk(png + offset, "IHDR", header, sizeof(header));
    offset += write_chunk(png + offset, "IDAT", compressed, (size_t)compressed_size);
    offset += write_chunk(png + offset, "IEND", NULL, 0);
    *written = offset;
    return true;
}

static bool challenge_digest(const struct captcha *captcha, const unsigned char *answer,
                             unsigned char result[CAPTCHA_DIGEST_BYTES])
{
    unsigned char payload[CAPTCHA_ID_BYTES + CAPTCHA_TEXT_SIZE];
    memcpy(payload, captcha->id, CAPTCHA_ID_BYTES);
    memcpy(payload + CAPTCHA_ID_BYTES, answer, CAPTCHA_TEXT_SIZE);
    unsigned int written = 0;
    bool success = HMAC(EVP_sha256(), captcha_key, CAPTCHA_DIGEST_BYTES, payload, sizeof(payload), result, &written) &&
                   written == CAPTCHA_DIGEST_BYTES;
    OPENSSL_cleanse(payload, sizeof(payload));
    return success;
}

bool panel_security_captcha_create(const char *ip, char id[PANEL_SECURITY_CAPTCHA_ID_SIZE],
                                  unsigned char *png, size_t capacity, size_t *size)
{
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    static const char hex[] = "0123456789abcdef";
    struct captcha next = {0};
    uint64_t now = monotonic_seconds();
    if (!id || !png || !size || !now || !parse_address(ip, &next.address) ||
        !panel_security_login_needs_captcha(ip) || panel_security_retry_after(ip))
        return false;
    size_t owned = 0;
    struct captcha *free_slot = NULL;
    struct captcha *earliest = NULL;
    for (size_t i = 0; i < CAPTCHA_SLOTS; ++i) {
        struct captcha *slot = &captchas[i];
        if (now >= slot->deadline) {
            if (!free_slot)
                free_slot = slot;
        } else if (same_address(&slot->address, &next.address)) {
            ++owned;
            if (!earliest || slot->deadline < earliest->deadline)
                earliest = slot;
        }
    }
    if (owned >= CAPTCHA_IP_LIMIT)
        free_slot = earliest;
    if (!free_slot)
        return false;
    if (!has_captcha_key) {
        has_captcha_key = RAND_bytes(captcha_key, sizeof(captcha_key)) == 1;
        if (!has_captcha_key)
            return false;
    }
    unsigned char selection[CAPTCHA_TEXT_SIZE];
    unsigned char answer[CAPTCHA_TEXT_SIZE];
    uint32_t seed;
    if (RAND_bytes(next.id, sizeof(next.id)) != 1 || RAND_bytes(selection, sizeof(selection)) != 1 ||
        RAND_bytes((unsigned char *)&seed, sizeof(seed)) != 1)
        return false;
    for (size_t i = 0; i < CAPTCHA_TEXT_SIZE; ++i) {
        selection[i] &= 31;
        answer[i] = (unsigned char)alphabet[selection[i]];
    }
    bool success = challenge_digest(&next, answer, next.digest) && challenge_png(selection, seed, png, capacity, size);
    OPENSSL_cleanse(answer, sizeof(answer));
    OPENSSL_cleanse(selection, sizeof(selection));
    if (!success)
        return false;
    next.deadline = now + CAPTCHA_SECONDS;
    *free_slot = next;
    for (size_t i = 0; i < sizeof(next.id); ++i) {
        id[2 * i] = hex[next.id[i] >> 4];
        id[2 * i + 1] = hex[next.id[i] & 15];
    }
    id[PANEL_SECURITY_CAPTCHA_ID_SIZE - 1] = '\0';
    return true;
}

static bool normalize_challenge_answer(const char *answer, unsigned char normalized[CAPTCHA_TEXT_SIZE])
{
    if (!answer)
        return false;
    size_t length = strlen(answer);
    if (length > 64)
        return false;
    const char *end = answer + length;
    char trimmed[CAPTCHA_TEXT_SIZE + 1];
    if (!trim_copy(answer, end, trimmed, sizeof(trimmed)) || strlen(trimmed) != CAPTCHA_TEXT_SIZE)
        return false;
    for (size_t i = 0; i < CAPTCHA_TEXT_SIZE; ++i) {
        char ch = trimmed[i];
        normalized[i] = (unsigned char)(ch >= 'a' && ch <= 'z' ? ch - 'a' + 'A' : ch);
    }
    OPENSSL_cleanse(trimmed, sizeof(trimmed));
    return true;
}

bool panel_security_captcha_verify(const char *ip, const char *id, const char *answer)
{
    struct ip_address address = {0};
    uint64_t now = monotonic_seconds();
    unsigned char binary_id[CAPTCHA_ID_BYTES];
    if (!now || !id || strlen(id) != PANEL_SECURITY_CAPTCHA_ID_SIZE - 1 || !parse_address(ip, &address))
        return false;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(binary_id); ++i) {
        const char *hi = strchr(hex, id[2 * i]);
        const char *lo = strchr(hex, id[2 * i + 1]);
        if (!hi || !lo)
            return false;
        binary_id[i] = (unsigned char)((hi - hex) * 16 + (lo - hex));
    }
    for (size_t i = 0; i < CAPTCHA_SLOTS; ++i) {
        struct captcha *slot = &captchas[i];
        if (now >= slot->deadline || !same_address(&slot->address, &address) ||
            CRYPTO_memcmp(slot->id, binary_id, sizeof(binary_id)) != 0)
            continue;
        slot->deadline = 0;
        unsigned char normalized[CAPTCHA_TEXT_SIZE];
        unsigned char result[CAPTCHA_DIGEST_BYTES];
        bool success = normalize_challenge_answer(answer, normalized) && challenge_digest(slot, normalized, result) &&
                       CRYPTO_memcmp(slot->digest, result, sizeof(slot->digest)) == 0;
        OPENSSL_cleanse(slot->digest, sizeof(slot->digest));
        OPENSSL_cleanse(result, sizeof(result));
        OPENSSL_cleanse(normalized, sizeof(normalized));
        return success;
    }
    return false;
}
