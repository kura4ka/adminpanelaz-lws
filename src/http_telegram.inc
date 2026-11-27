static int telegram_error(struct lws *wsi, struct session *session, enum panel_telegram_result result)
{
    switch (result) {
    case PANEL_TELEGRAM_DISABLED: return error_reply(wsi, session, 503, "telegram_disabled");
    case PANEL_TELEGRAM_DENIED: return error_reply(wsi, session, 401, "telegram_login_failed");
    case PANEL_TELEGRAM_CONFLICT: return error_reply(wsi, session, 409, "telegram_already_linked");
    case PANEL_TELEGRAM_REPLAY: return error_reply(wsi, session, 401, "telegram_login_failed");
    case PANEL_TELEGRAM_INVALID: return error_reply(wsi, session, 400, "invalid_telegram_form");
    default: return error_reply(wsi, session, 500, "telegram_store_error");
    }
}

static int telegram_settings_reply(struct lws *wsi, struct session *session, bool public)
{
    struct panel_telegram_settings settings;
    if (!panel_telegram_settings_get(&settings))
        return error_reply(wsi, session, 503, "telegram_disabled");
    const char *legacy = settings.legacy_enabled ? "true" : "false";
    const char *mini = settings.mini_enabled ? "true" : "false";
    if (public) {
        bool ready = settings.legacy_enabled && settings.token_configured && settings.username[0];
        snprintf(session->response, sizeof(session->response),
            "{\"enabled\":%s,\"module_enabled\":true,\"legacy_enabled\":%s,\"mini_enabled\":%s,"
            "\"bot_username\":\"%s\",\"max_age_seconds\":%u,\"auth_method\":\"%s\",\"oidc_enabled\":false}",
            ready ? "true" : "false", ready ? "true" : "false", mini, ready ? settings.username : "",
            settings.max_age, ready ? "legacy" : "none");
    } else {
        snprintf(session->response, sizeof(session->response),
            "{\"bot_username\":\"%s\",\"bot_token_set\":%s,\"auth_max_age_seconds\":%u,"
            "\"legacy_login_enabled\":%s,\"mini_enabled\":%s}", settings.username,
            settings.token_configured ? "true" : "false", settings.max_age, legacy, mini);
    }
    return reply(wsi, session, 200, session->response);
}

static bool telegram_form_switch(const char *value, bool *out)
{
    if (!value || (strcmp(value, "true") && strcmp(value, "false")))
        return false;
    *out = value[0] == 't';
    return true;
}

static bool telegram_actor(struct lws *wsi, struct panel_auth_identity *identity)
{
    return current_identity(wsi, identity) && !identity->must_change_password;
}

static int telegram_settings_form(struct lws *wsi, struct session *session, const struct form *form)
{
    struct panel_auth_identity actor;
    if (!panel_auth_identify(session->current_token, &actor) || actor.must_change_password ||
        actor.role != PANEL_AUTH_ROLE_ADMIN)
        return error_reply(wsi, session, 403, "admin_required");
    const char *name = form_value(form, "bot_username");
    const char *age = form_value(form, "auth_max_age_seconds");
    const char *token = form_value(form, "bot_token");
    struct panel_telegram_settings settings = {0};
    if (!name || !age || form->count != (token ? 5U : 4U) || strlen(age) > 5 ||
        !*age || strspn(age, "0123456789") != strlen(age) ||
        !telegram_form_switch(form_value(form, "legacy_login_enabled"), &settings.legacy_enabled) ||
        !telegram_form_switch(form_value(form, "mini_enabled"), &settings.mini_enabled))
        return telegram_error(wsi, session, PANEL_TELEGRAM_INVALID);
    if (name[0] == '@')
        ++name;
    if (strlen(name) >= sizeof(settings.username))
        return telegram_error(wsi, session, PANEL_TELEGRAM_INVALID);
    memcpy(settings.username, name, strlen(name) + 1);
    settings.max_age = (unsigned int)strtoul(age, NULL, 10);
    enum panel_telegram_result result = panel_telegram_settings_set(&settings, token);
    panel_history_audit((int64_t)time(NULL), actor.id, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_TELEGRAM_OK);
    return result == PANEL_TELEGRAM_OK ? telegram_settings_reply(wsi, session, false) : telegram_error(wsi, session, result);
}

static int telegram_status_reply(struct lws *wsi, struct session *session, int64_t account_id)
{
    uint64_t telegram_id;
    if (!panel_telegram_bound(account_id, &telegram_id))
        return telegram_error(wsi, session, PANEL_TELEGRAM_ERROR);
    if (telegram_id) {
        snprintf(session->response, sizeof(session->response), "{\"telegram_id\":\"%" PRIu64 "\"}", telegram_id);
        return reply(wsi, session, 200, session->response);
    }
    return reply(wsi, session, 200, "{\"telegram_id\":null}");
}

static const char *telegram_proof_form(const struct form *form, size_t fields, bool *mini)
{
    const char *mode = form_value(form, "mode");
    const char *data = form_value(form, "data");
    if (form->count != fields || !mode || (strcmp(mode, "widget") && strcmp(mode, "mini")) || !data || !*data)
        return NULL;
    *mini = mode[0] == 'm';
    return data;
}

static int telegram_link_form(struct lws *wsi, struct session *session, const struct form *form)
{
    struct panel_auth_identity identity;
    if (!panel_auth_identify(session->current_token, &identity) || identity.must_change_password)
        return error_reply(wsi, session, 401, "unauthorized");
    bool mini;
    const char *data = telegram_proof_form(form, 2, &mini);
    time_t now = time(NULL);
    if (!data || now < 0)
        return telegram_error(wsi, session, PANEL_TELEGRAM_INVALID);
    enum panel_telegram_result result = panel_telegram_link(identity.id, mini, data, strlen(data), (uint64_t)now);
    panel_history_audit((int64_t)now, identity.id, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_TELEGRAM_OK);
    return result == PANEL_TELEGRAM_OK ? telegram_status_reply(wsi, session, identity.id) : telegram_error(wsi, session, result);
}

static int telegram_login_form(struct lws *wsi, struct session *session, const struct form *form)
{
    const char *ip = session->remote_ip;
    session->retry_after = panel_security_retry_after(ip);
    if (session->retry_after)
        return error_reply(wsi, session, 429, "too_many_attempts");

    bool mini;
    const char *code = form_value(form, "code");
    const char *captcha_id = form_value(form, "captcha_id");
    const char *captcha_answer = form_value(form, "captcha_answer");
    const char *data = telegram_proof_form(form, 2U + (code ? 1U : 0U) +
        (captcha_id ? 1U : 0U) + (captcha_answer ? 1U : 0U), &mini);
    time_t now = time(NULL);
    if (!data || now < 0)
        return telegram_error(wsi, session, PANEL_TELEGRAM_INVALID);
    if (panel_security_login_needs_captcha(ip) && !panel_security_captcha_verify(ip, captcha_id, captcha_answer))
        return error_reply(wsi, session, 401, "captcha_required");
    size_t size = strlen(data);
    int64_t account;
    enum panel_telegram_result result = panel_telegram_check_login(mini, data, size, (uint64_t)now, &account);
    if (result != PANEL_TELEGRAM_OK) {
        if (result == PANEL_TELEGRAM_DENIED || result == PANEL_TELEGRAM_REPLAY) {
            panel_security_record_login(ip, false);
            panel_history_audit((int64_t)now, 0, PANEL_HISTORY_LOGIN, false);
        }
        return telegram_error(wsi, session, result);
    }
    bool enrolled;
    unsigned int remaining;
    if (!panel_security_factor_status(account, &enrolled, &remaining))
        return telegram_error(wsi, session, PANEL_TELEGRAM_ERROR);
    if (enrolled && (!code || !*code))
        return error_reply(wsi, session, 401, "second_factor_required");
    if (!panel_auth_external_login(account, session->cookie, panel_security_second_factor, (void *)code)) {
        panel_security_record_login(ip, false);
        panel_history_audit((int64_t)now, 0, PANEL_HISTORY_LOGIN, false);
        return error_reply(wsi, session, 401, "telegram_login_failed");
    }

    struct panel_auth_identity identity;
    int64_t claimed;
    result = panel_telegram_claim_login(mini, data, size, (uint64_t)now, &claimed);
    if (result != PANEL_TELEGRAM_OK || claimed != account || !panel_auth_identify(session->cookie, &identity)) {
        panel_auth_logout(session->cookie);
        OPENSSL_cleanse(session->cookie, sizeof(session->cookie));
        return telegram_error(wsi, session, result == PANEL_TELEGRAM_OK ? PANEL_TELEGRAM_ERROR : result);
    }
    panel_security_record_login(ip, true);
    panel_history_audit((int64_t)now, identity.id, PANEL_HISTORY_LOGIN, true);
    int reply_result = reply_identity(wsi, session, &identity);
    if (session->status != 200) {
        panel_auth_logout(session->cookie);
        OPENSSL_cleanse(session->cookie, sizeof(session->cookie));
    }
    return reply_result;
}

static int telegram_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    if (!strcmp(uri, "/api/auth/telegram/config") || !strcmp(uri, "/api/telegram/config"))
        return method == LWSHUMETH_GET ? telegram_settings_reply(wsi, session, true) :
               error_reply(wsi, session, 405, "method_not_allowed");
    const char *route = uri + sizeof("/api/telegram/") - 1;
    if (method == LWSHUMETH_GET) {
        if (!strcmp(route, "settings")) {
            struct panel_auth_identity actor;
            return telegram_actor(wsi, &actor) && actor.role == PANEL_AUTH_ROLE_ADMIN ?
                   telegram_settings_reply(wsi, session, false) :
                   error_reply(wsi, session, 403, "admin_required");
        }
        if (!strcmp(route, "status")) {
            struct panel_auth_identity identity;
            return telegram_actor(wsi, &identity) ? telegram_status_reply(wsi, session, identity.id) :
                   error_reply(wsi, session, 401, "unauthorized");
        }
        return error_reply(wsi, session, 404, "not_found");
    }
    if (method != LWSHUMETH_POST)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (!lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) || !same_origin(wsi))
        return error_reply(wsi, session, 403, "invalid_origin");
    if (!strcmp(route, "login"))
        return begin_form(wsi, session, telegram_login_form);

    struct panel_auth_identity identity;
    bool authenticated = session_token(wsi, session->current_token) &&
        panel_auth_identify(session->current_token, &identity) && !identity.must_change_password;
    if (!strcmp(route, "settings"))
        return authenticated && identity.role == PANEL_AUTH_ROLE_ADMIN ? begin_form(wsi, session, telegram_settings_form) :
               error_reply(wsi, session, 403, "admin_required");
    if (!authenticated)
        return error_reply(wsi, session, 401, "unauthorized");
    if (!strcmp(route, "link"))
        return begin_form(wsi, session, telegram_link_form);
    if (!strcmp(route, "unlink")) {
        uint64_t bound;
        bool success = panel_telegram_bound(identity.id, &bound) && (!bound ||
            (panel_auth_revoke_other_sessions(identity.id, session->current_token) && panel_telegram_unlink(identity.id)));
        panel_history_audit((int64_t)time(NULL), identity.id, PANEL_HISTORY_SETTINGS_CHANGE, success);
        return success ? telegram_status_reply(wsi, session, identity.id) : telegram_error(wsi, session, PANEL_TELEGRAM_ERROR);
    }
    return error_reply(wsi, session, 404, "not_found");
}
