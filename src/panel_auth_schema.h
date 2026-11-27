#ifndef PANEL_AUTH_SCHEMA_H
#define PANEL_AUTH_SCHEMA_H

#include "panel_auth.h"

#define PANEL_ACCOUNTS_COLUMNS " (" \
    " id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE," \
    " password_salt BLOB NOT NULL CHECK(length(password_salt) = 16)," \
    " password_hash BLOB NOT NULL CHECK(length(password_hash) = 32)," \
    " iterations INTEGER NOT NULL CHECK(iterations >= 300000)" \
    ")"
#define PANEL_SESSIONS_COLUMNS " (" \
    " token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32)," \
    " account_id INTEGER NOT NULL REFERENCES panel_accounts(id) ON DELETE CASCADE," \
    " expires_at INTEGER NOT NULL" \
    ") WITHOUT ROWID"
#define PANEL_LEGACY_ACCOUNTS_COMMON " (" \
    " account_id INTEGER PRIMARY KEY REFERENCES panel_accounts(id) ON DELETE CASCADE," \
    " bcrypt_hash TEXT CHECK(bcrypt_hash IS NULL OR length(bcrypt_hash) = 60)," \
    " role TEXT NOT NULL CHECK(role IN ('admin', 'user'))," \
    " is_active INTEGER NOT NULL CHECK(is_active IN (0, 1))," \
    " panel_login_enabled INTEGER NOT NULL CHECK(panel_login_enabled IN (0, 1))," \
    " must_change_password INTEGER NOT NULL CHECK(must_change_password IN (0, 1))," \
    " totp_enabled INTEGER NOT NULL CHECK(totp_enabled IN (0, 1))," \
    " has_passkeys INTEGER NOT NULL CHECK(has_passkeys IN (0, 1))," \
    " native_password_set INTEGER NOT NULL CHECK(native_password_set IN (0, 1))," \
    " access_until TEXT," \
    " from_legacy INTEGER NOT NULL DEFAULT 1 CHECK(from_legacy IN (0, 1)),"
#define PANEL_LEGACY_ACCOUNTS_REVISION \
    " revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(revision) = 'integer' AND revision > 0)"
#define PANEL_LEGACY_ACCOUNTS_PRE_MARKER_COLUMNS \
    PANEL_LEGACY_ACCOUNTS_COMMON PANEL_LEGACY_ACCOUNTS_REVISION ")"
#define PANEL_LEGACY_ACCOUNTS_COLUMNS \
    PANEL_LEGACY_ACCOUNTS_COMMON \
    " native_totp_required INTEGER NOT NULL DEFAULT 0 CHECK(native_totp_required IN (0, 1))," \
    PANEL_LEGACY_ACCOUNTS_REVISION ")"
#define PANEL_ACCOUNT_IDS_COLUMNS " (" \
    " singleton INTEGER PRIMARY KEY CHECK(singleton = 1)," \
    " high_watermark INTEGER NOT NULL CHECK(typeof(high_watermark) = 'integer' AND high_watermark > 0)" \
    ")"

#define PANEL_AUTH_SCHEMA \
    "CREATE TABLE IF NOT EXISTS panel_accounts" PANEL_ACCOUNTS_COLUMNS ";" \
    "CREATE TABLE IF NOT EXISTS panel_sessions" PANEL_SESSIONS_COLUMNS ";" \
    "CREATE INDEX IF NOT EXISTS panel_sessions_expiry ON panel_sessions(expires_at);" \
    "CREATE TABLE IF NOT EXISTS panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_COLUMNS ";" \
    "CREATE TABLE IF NOT EXISTS panel_account_ids" PANEL_ACCOUNT_IDS_COLUMNS ";"

static inline bool panel_auth_valid_username(const unsigned char *name, size_t bytes)
{
    if (!name || !bytes || bytes > PANEL_AUTH_USERNAME_MAX)
        return false;
    unsigned int characters = 0;
    for (size_t offset = 0; offset < bytes && ++characters <= PANEL_AUTH_USERNAME_CHARACTERS;) {
        unsigned int value = name[offset++];
        if (value > 0 && value < 0x80)
            continue;
        unsigned int octets;
        unsigned int minimum;
        if (value >= 0xc2 && value <= 0xdf) {
            octets = 1;
            minimum = 0x80;
            value &= 0x1f;
        } else if (value >= 0xe0 && value <= 0xef) {
            octets = 2;
            minimum = 0x800;
            value &= 0x0f;
        } else if (value >= 0xf0 && value <= 0xf4) {
            octets = 3;
            minimum = 0x10000;
            value &= 0x07;
        } else {
            return false;
        }
        if (octets > bytes - offset)
            return false;
        for (unsigned int part = 0; part < octets; ++part) {
            unsigned int next = name[offset++];
            if ((next & 0xc0) != 0x80)
                return false;
            value = (value << 6) | (next & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            return false;
    }
    return characters <= PANEL_AUTH_USERNAME_CHARACTERS;
}

#endif
