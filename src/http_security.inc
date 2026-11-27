static int login_captcha_request(struct lws *wsi, struct session *session, int method)
{
    if (method != LWSHUMETH_GET)
        return error_reply(wsi, session, 405, "method_not_allowed");
    char ip[PANEL_SECURITY_IP_SIZE];
    if (!request_ip(wsi, ip))
        return error_reply(wsi, session, 403, "unrecognized_peer");
    session->retry_after = panel_security_retry_after(ip);
    if (session->retry_after)
        return error_reply(wsi, session, 429, "too_many_attempts");
    if (!panel_security_login_needs_captcha(ip))
        return error_reply(wsi, session, 404, "captcha_not_required");
    char id[PANEL_SECURITY_CAPTCHA_ID_SIZE];
    unsigned char png[PANEL_SECURITY_CAPTCHA_PNG_MAX];
    size_t size;
    if (!panel_security_captcha_create(ip, id, png, sizeof(png), &size))
        return error_reply(wsi, session, 503, "captcha_unavailable");
    static const char prefix[] = "{\"id\":\"%s\",\"image\":\"data:image/png;base64,";
    size_t capacity = sizeof(prefix) + sizeof(id) + 4 * ((size + 2) / 3) + 2;
    char *json = malloc(capacity);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    int offset = snprintf(json, capacity, prefix, id);
    int encoded = EVP_EncodeBlock((unsigned char *)json + offset, png, (int)size);
    if (encoded < 1) {
        free(json);
        return error_reply(wsi, session, 503, "captcha_unavailable");
    }
    memcpy(json + offset + encoded, "\"}", 3);
    return allocated_reply(wsi, session, 200, json);
}

static bool factor_identity(struct lws *wsi, struct session *session, struct panel_auth_identity *identity)
{
    if (!current_identity(wsi, identity)) {
        error_reply(wsi, session, 401, "unauthorized");
        return false;
    }
    if (identity->must_change_password) {
        error_reply(wsi, session, 403, "password_change_required");
        return false;
    }
    return true;
}

static int factor_status(struct lws *wsi, struct session *session, int64_t account_id)
{
    bool enabled;
    unsigned int remaining;
    if (!panel_security_factor_status(account_id, &enabled, &remaining))
        return error_reply(wsi, session, 503, "totp_unavailable");
    bool required = panel_auth_totp_required(account_id);
    snprintf(session->response, sizeof(session->response),
             "{\"enabled\":%s,\"configured\":%s,\"legacy_required\":%s,\"required\":%s,\"pending\":%s,"
             "\"recovery_codes_remaining\":%u}",
             enabled ? "true" : "false", panel_security_can_enroll() ? "true" : "false",
             panel_auth_legacy_totp_required(account_id) ? "true" : "false", required ? "true" : "false",
             required && panel_security_factor_pending(account_id) ? "true" : "false", remaining);
    return reply(wsi, session, 200, session->response);
}

static int factor_setup(struct lws *wsi, struct session *session, int64_t account_id)
{
    bool enabled;
    unsigned int remaining;
    if (!panel_security_factor_status(account_id, &enabled, &remaining) || !panel_security_can_enroll())
        return error_reply(wsi, session, 503, "totp_unavailable");
    if (enabled)
        return error_reply(wsi, session, 409, "totp_already_enabled");
    if (panel_auth_totp_required(account_id))
        return error_reply(wsi, session, 409, "totp_incomplete");
    char secret[PANEL_SECURITY_TOTP_SECRET_SIZE];
    if (!panel_security_factor_setup(account_id, secret))
        return error_reply(wsi, session, 503, "totp_unavailable");
    snprintf(session->response, sizeof(session->response), "{\"secret\":\"%s\"}", secret);
    OPENSSL_cleanse(secret, sizeof(secret));
    session->close_after_reply = true;
    return reply(wsi, session, 200, session->response);
}

enum factor_action { FACTOR_ENABLE, FACTOR_DISABLE, FACTOR_ROTATE };

static int factor_change(struct lws *wsi, struct session *session, const struct form *form, enum factor_action action)
{
    struct panel_auth_identity identity;
    if (!factor_identity(wsi, session, &identity))
        return 0;
    const char *code = form_value(form, "code");
    if (form->count != 1 || !code || !*code)
        return error_reply(wsi, session, 400, "invalid_auth_form");
    if (!panel_security_can_enroll())
        return error_reply(wsi, session, 503, "totp_unavailable");
    if (action == FACTOR_DISABLE && panel_auth_legacy_totp_required(identity.id))
        return error_reply(wsi, session, 409, "legacy_totp_required");
    char ip[PANEL_SECURITY_IP_SIZE];
    if (!request_ip(wsi, ip))
        return error_reply(wsi, session, 403, "unrecognized_peer");
    session->retry_after = panel_security_retry_after(ip);
    if (session->retry_after)
        return error_reply(wsi, session, 429, "too_many_attempts");

    char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE];
    bool changed;
    switch (action) {
    case FACTOR_ENABLE:
        changed = panel_security_factor_enable(identity.id, code, codes, panel_auth_set_native_totp_required);
        break;
    case FACTOR_DISABLE:
        changed = panel_security_factor_disable(identity.id, code);
        if (changed && !panel_auth_set_native_totp_required(identity.id, false)) {
            audit(wsi, PANEL_HISTORY_SETTINGS_CHANGE, false);
            return error_reply(wsi, session, 503, "totp_incomplete");
        }
        break;
    case FACTOR_ROTATE:
        changed = panel_security_factor_recovery(identity.id, code, codes);
        break;
    default:
        return error_reply(wsi, session, 500, "totp_unavailable");
    }
    audit(wsi, PANEL_HISTORY_SETTINGS_CHANGE, changed);
    if (!changed) {
        panel_security_record_login(ip, false);
        return error_reply(wsi, session, 400, "invalid_second_factor");
    }

    bool revoked = action == FACTOR_ROTATE || panel_auth_revoke_other_sessions(identity.id, session->current_token);
    size_t offset = (size_t)snprintf(session->response, sizeof(session->response),
                                    "{\"sessions_revoked\":%s,\"recovery_codes\":[", revoked ? "true" : "false");
    if (action != FACTOR_DISABLE) {
        for (size_t i = 0; i < PANEL_SECURITY_RECOVERY_COUNT; ++i) {
            offset += (size_t)snprintf(session->response + offset, sizeof(session->response) - offset,
                                       "%s\"%s\"", i ? "," : "", codes[i]);
        }
    }
    memcpy(session->response + offset, "]}", 3);
    OPENSSL_cleanse(codes, sizeof(codes));
    session->close_after_reply = true;
    return reply(wsi, session, 200, session->response);
}

static int factor_enable_form(struct lws *wsi, struct session *session, const struct form *form)
{
    return factor_change(wsi, session, form, FACTOR_ENABLE);
}

static int factor_disable_form(struct lws *wsi, struct session *session, const struct form *form)
{
    return factor_change(wsi, session, form, FACTOR_DISABLE);
}

static int factor_rotate_form(struct lws *wsi, struct session *session, const struct form *form)
{
    return factor_change(wsi, session, form, FACTOR_ROTATE);
}

static int security_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    if (!config.auth_db)
        return error_reply(wsi, session, 404, "not_found");
    if (!strcmp(uri, "/api/auth/captcha"))
        return login_captcha_request(wsi, session, method);
    struct panel_auth_identity identity;
    if (!factor_identity(wsi, session, &identity))
        return 0;
    if (!strcmp(uri, "/api/auth/totp"))
        return method == LWSHUMETH_GET ? factor_status(wsi, session, identity.id) :
               error_reply(wsi, session, 405, "method_not_allowed");
    if (method != LWSHUMETH_POST)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (!same_origin(wsi))
        return error_reply(wsi, session, 403, "unexpected_origin");
    if (!strcmp(uri, "/api/auth/totp/setup"))
        return factor_setup(wsi, session, identity.id);
    if (!strcmp(uri, "/api/auth/totp/enable"))
        return begin_form(wsi, session, factor_enable_form);
    if (!strcmp(uri, "/api/auth/totp/disable"))
        return begin_form(wsi, session, factor_disable_form);
    if (!strcmp(uri, "/api/auth/totp/recovery"))
        return begin_form(wsi, session, factor_rotate_form);
    return error_reply(wsi, session, 404, "not_found");
}
