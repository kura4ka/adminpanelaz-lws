#define USERS_API "/api/settings/users"

static const char *json_boolean(bool value)
{
    return value ? "true" : "false";
}

static void user_json_name(const char *name, char out[PANEL_AUTH_USERNAME_MAX * 6 + 1])
{
    for (const unsigned char *input = (const unsigned char *)name; *input; ++input) {
        if (*input < 32) {
            snprintf(out, 7, "\\u%04x", (unsigned int)*input);
            out += 6;
        } else {
            if (*input == '"' || *input == '\\')
                *out++ = '\\';
            *out++ = (char)*input;
        }
    }
    *out = '\0';
}

static int users_list(struct lws *wsi, struct session *session)
{
    char cursor[32];
    char search[PANEL_AUTH_USERNAME_MAX + 3];
    const char *after_argument = lws_get_urlarg_by_name(wsi, "after=", cursor, sizeof(cursor));
    int64_t after = 0;
    if (after_argument && !parse_resource_id(after_argument, &after, NULL))
        return error_reply(wsi, session, 400, "invalid_cursor");

    struct panel_auth_user users[PANEL_AUTH_USERS_PAGE];
    size_t count;
    bool has_more;
    const char *query = lws_get_urlarg_by_name(wsi, "q=", search, sizeof(search));
    if (query && strlen(query) > PANEL_AUTH_USERNAME_MAX)
        return error_reply(wsi, session, 400, "invalid_search");
    if (!panel_auth_users(after, query, users, &count, &has_more))
        return error_reply(wsi, session, 503, "users_unavailable");
    enum { JSON_SIZE = PANEL_AUTH_USERS_PAGE * (PANEL_AUTH_USERNAME_MAX * 6 + 256) + 128 };
    char *json = malloc(JSON_SIZE);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    static const char opening[] = "{\"users\":[";
    memcpy(json, opening, sizeof(opening));
    size_t offset = sizeof(opening) - 1;
    for (size_t i = 0; i < count; ++i) {
        const struct panel_auth_user *user = &users[i];
        uint64_t telegram_id;
        char name[PANEL_AUTH_USERNAME_MAX * 6 + 1];
        user_json_name(user->identity.username, name);
        int bytes = snprintf(json + offset, JSON_SIZE - offset,
            "%s{\"id\":\"%" PRId64 "\",\"username\":\"%s\",\"role\":\"%s\",\"revision\":\"%" PRId64 "\","
            "\"is_active\":%s,\"panel_login_enabled\":%s,\"must_change_password\":%s,\"legacy_totp\":%s,"
            "\"legacy_passkeys\":%s,\"native_totp_required\":%s,\"totp_available\":%s,\"telegram_linked\":%s}",
            i ? "," : "", user->identity.id, name, user->settings.role == PANEL_AUTH_ROLE_ADMIN ? "admin" : "user",
            user->revision, json_boolean(user->settings.is_active), json_boolean(user->settings.panel_login_enabled),
            json_boolean(user->settings.must_change_password), json_boolean(user->legacy_totp),
            json_boolean(user->legacy_passkeys), json_boolean(user->native_totp_required),
            json_boolean((user->legacy_totp || user->native_totp_required) && panel_security_factor_is_enabled(user->identity.id)),
            json_boolean(panel_telegram_bound(user->identity.id, &telegram_id)));
        if (bytes < 0 || (size_t)bytes >= JSON_SIZE - offset) {
            free(json);
            return error_reply(wsi, session, 500, "users_response_too_large");
        }
        offset += (size_t)bytes;
    }
    if (has_more)
        snprintf(json + offset, JSON_SIZE - offset, "],\"next_after\":\"%" PRId64 "\"}", users[count - 1].identity.id);
    else
        snprintf(json + offset, JSON_SIZE - offset, "],\"next_after\":null}");
    return allocated_reply(wsi, session, 200, json);
}

static int users_result(struct lws *wsi, struct session *session, enum panel_auth_user_result result)
{
    switch (result) {
    case PANEL_AUTH_USER_OK: return reply(wsi, session, 200, "{\"status\":\"ok\"}");
    case PANEL_AUTH_USER_INVALID: return error_reply(wsi, session, 400, "invalid_user");
    case PANEL_AUTH_USER_NOT_FOUND: return error_reply(wsi, session, 404, "user_not_found");
    case PANEL_AUTH_USER_EXISTS: return error_reply(wsi, session, 409, "username_taken");
    case PANEL_AUTH_USER_STALE: return error_reply(wsi, session, 409, "stale_user");
    case PANEL_AUTH_USER_LAST_ADMIN: return error_reply(wsi, session, 409, "last_admin");
    case PANEL_AUTH_USER_SELF: return error_reply(wsi, session, 403, "use_personal_settings");
    case PANEL_AUTH_USER_ERROR: return error_reply(wsi, session, 503, "users_unavailable");
    }
    return error_reply(wsi, session, 500, "users_error");
}

static bool user_form_flag(const struct form *form, const char *name, bool *out)
{
    const char *value = form_value(form, name);
    if (!value || (strcmp(value, "0") && strcmp(value, "1")))
        return false;
    *out = *value == '1';
    return true;
}

static bool user_form_settings(const struct form *form, struct panel_auth_user_settings *settings)
{
    const char *role = form_value(form, "role");
    if (!role || (strcmp(role, "admin") && strcmp(role, "user")))
        return false;
    settings->role = *role == 'a' ? PANEL_AUTH_ROLE_ADMIN : PANEL_AUTH_ROLE_USER;
    return user_form_flag(form, "is_active", &settings->is_active) &&
           user_form_flag(form, "panel_login_enabled", &settings->panel_login_enabled) &&
           user_form_flag(form, "must_change_password", &settings->must_change_password);
}

static int user_create_form(struct lws *wsi, struct session *session, const struct form *form)
{
    if (!require_admin(wsi, session, LWSHUMETH_POST, "user_management"))
        return 0;
    const char *username = form_value(form, "username");
    const char *password = form_value(form, "password");
    struct panel_auth_user_settings settings;
    if (form->count != 6 || !username || !password || !user_form_settings(form, &settings))
        return error_reply(wsi, session, 400, "invalid_user");
    int64_t id;
    enum panel_auth_user_result result = panel_auth_user_create(username, password, &settings, &id);
    audit(wsi, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_AUTH_USER_OK);
    if (result != PANEL_AUTH_USER_OK)
        return users_result(wsi, session, result);
    snprintf(session->response, sizeof(session->response), "{\"id\":\"%" PRId64 "\"}", id);
    return reply(wsi, session, 201, session->response);
}

static int user_update_form(struct lws *wsi, struct session *session, const struct form *form)
{
    if (!require_admin(wsi, session, LWSHUMETH_PUT, "user_management"))
        return 0;
    struct panel_auth_user_settings settings;
    int64_t revision;
    if (form->count != 5 || !user_form_settings(form, &settings) ||
        !parse_resource_id(form_value(form, "revision"), &revision, NULL))
        return error_reply(wsi, session, 400, "invalid_user");
    struct panel_auth_identity actor;
    if (!current_identity(wsi, &actor))
        return error_reply(wsi, session, 401, "unauthorized");
    enum panel_auth_user_result result = panel_auth_user_update(session->resource_id, revision, &settings,
        panel_security_factor_is_enabled);
    panel_history_audit((int64_t)time(NULL), actor.id, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_AUTH_USER_OK);
    return users_result(wsi, session, result);
}

static int user_password_form(struct lws *wsi, struct session *session, const struct form *form)
{
    if (!require_admin(wsi, session, LWSHUMETH_POST, "user_management"))
        return 0;
    struct panel_auth_identity identity;
    if (!current_identity(wsi, &identity))
        return error_reply(wsi, session, 401, "unauthorized");
    const char *password = form_value(form, "password");
    int64_t revision;
    bool must_change;
    if (form->count != 3 || !password ||
        !parse_resource_id(form_value(form, "revision"), &revision, NULL) ||
        !user_form_flag(form, "must_change_password", &must_change))
        return error_reply(wsi, session, 400, "invalid_user");
    enum panel_auth_user_result result = panel_auth_user_reset(identity.id, session->resource_id, revision, password,
        must_change);
    audit(wsi, PANEL_HISTORY_PASSWORD_CHANGE, result == PANEL_AUTH_USER_OK);
    return users_result(wsi, session, result);
}

static int user_remove(struct lws *wsi, struct session *session)
{
    struct panel_auth_identity identity;
    if (!current_identity(wsi, &identity))
        return error_reply(wsi, session, 401, "unauthorized");
    char expected[32];
    int64_t revision;
    if (!parse_resource_id(lws_get_urlarg_by_name(wsi, "revision=", expected, sizeof(expected)), &revision, NULL))
        return error_reply(wsi, session, 400, "invalid_user");
    int64_t id = session->resource_id;
    enum panel_auth_user_result result = panel_auth_user_delete(identity.id, id, revision, panel_security_factor_is_enabled);
    audit(wsi, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_AUTH_USER_OK || result == PANEL_AUTH_USER_NOT_FOUND);
    if (result == PANEL_AUTH_USER_OK || result == PANEL_AUTH_USER_NOT_FOUND) {
        bool unlinked = panel_telegram_unlink(id);
        bool factor_removed = panel_security_factor_forget(id);
        if (!unlinked || !factor_removed)
            return error_reply(wsi, session, 503, "user_cleanup_pending");
        result = PANEL_AUTH_USER_OK;
    }
    return users_result(wsi, session, result);
}

static int accounts_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *path = uri + sizeof(USERS_API) - 1;
    if (!require_admin(wsi, session, method, "user_management"))
        return 0;
    if (!*path) {
        if (method == LWSHUMETH_GET)
            return users_list(wsi, session);
        if (method == LWSHUMETH_POST)
            return begin_form(wsi, session, user_create_form);
        return error_reply(wsi, session, 405, "method_not_allowed");
    }
    if (*path != '/' || !parse_resource_id(path + 1, &session->resource_id, &path) || session->resource_id <= 0)
        return error_reply(wsi, session, 404, "not_found");
    if (!strcmp(path, "/reset-password"))
        return method == LWSHUMETH_POST ? begin_form(wsi, session, user_password_form) :
               error_reply(wsi, session, 405, "method_not_allowed");
    if (*path)
        return error_reply(wsi, session, 404, "not_found");
    if (method == LWSHUMETH_PUT)
        return begin_form(wsi, session, user_update_form);
    if (method == LWSHUMETH_DELETE)
        return user_remove(wsi, session);
    return error_reply(wsi, session, 405, "method_not_allowed");
}
