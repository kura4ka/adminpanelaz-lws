static bool ha_node_lookup(int64_t id, struct panel_ha_node_info *info, void *context)
{
    (void)context;
    struct panel_node node;
    if (panel_nodes_get(id, &node) != PANEL_NODES_OK)
        return false;
    info->vpn = node.kind == PANEL_NODE_VPN;
    info->online = node.health == NODE_HEALTH_AVAILABLE;
    info->health_unknown = node.health == NODE_HEALTH_UNKNOWN;
    snprintf(info->antizapret_version, sizeof(info->antizapret_version), "%s", node.antizapret_version);
    snprintf(info->agent_version, sizeof(info->agent_version), "%s", node.agent_version);
    snprintf(info->name, sizeof(info->name), "%s", node.name);
    snprintf(info->host, sizeof(info->host), "%s", node.endpoint);
    return true;
}

static int ha_response(struct lws *wsi, struct session *session, const char *action, int64_t id,
                       const struct panel_ha_fields *fields, bool log_change)
{
    FILE *output = tmpfile();
    if (!output)
        return error_reply(wsi, session, 503, "ha_response_unavailable");
    char request_host[320];
    const char *host = getenv("APAZ_PANEL_HOST");
    if ((!host || !host[0]) &&
        lws_hdr_copy(wsi, request_host, (int)sizeof(request_host), WSI_TOKEN_HOST) > 0)
        host = request_host;
    int status = panel_ha_request(action, id, fields, host, ha_node_lookup, NULL, output);
    if (log_change)
        audit(wsi, PANEL_HISTORY_NODE_CHANGE, status < 300);
    if (status == 500) {
        fclose(output);
        return error_reply(wsi, session, 500, "ha_storage_error");
    }
    return file_reply(wsi, session, output, (unsigned int)status, "application/json; charset=utf-8");
}

static bool ha_parse_replicas(const char *text, struct panel_ha_fields *fields,
                              int64_t ids[PANEL_HA_MAX_REPLICAS])
{
    fields->replica_node_ids = ids;
    while (*text) {
        if (fields->replica_count == PANEL_HA_MAX_REPLICAS || *text < '0' || *text > '9')
            return false;
        char *end;
        errno = 0;
        intmax_t value = strtoimax(text, &end, 10);
        if (errno || value <= 0 || value > INT64_MAX || (*end && *end != ','))
            return false;
        ids[fields->replica_count++] = (int64_t)value;
        if (!*end)
            return true;
        text = end + 1;
        if (!*text)
            return false;
    }
    return true;
}

static int ha_fields_response(struct lws *wsi, struct session *session, const struct form *form,
                              const char *action, int64_t id, bool log_change)
{
    int64_t replicas[PANEL_HA_MAX_REPLICAS];
    struct panel_ha_fields fields = {
        .name = form_value(form, "name"),
        .shared_domain = form_value(form, "shared_domain"),
        .shared_domain_wireguard = form_value(form, "shared_domain_wireguard"),
        .sync_mode = form_value(form, "sync_mode")
    };
    const char *primary = form_value(form, "primary_node_id");
    const char *replica_list = form_value(form, "replica_node_ids");
    const char *rest = NULL;
    if ((primary && (!parse_resource_id(primary, &fields.primary_node_id, &rest) ||
                     fields.primary_node_id <= 0 || *rest)) ||
        (replica_list && !ha_parse_replicas(replica_list, &fields, replicas))) {
        if (log_change)
            audit(wsi, PANEL_HISTORY_NODE_CHANGE, false);
        return error_reply(wsi, session, 422, "invalid_ha_members");
    }
    return ha_response(wsi, session, action, id, &fields, log_change);
}

static int ha_save_form(struct lws *wsi, struct session *session, const struct form *form)
{
    int64_t id = session->resource_id;
    return ha_fields_response(wsi, session, form, id ? "update" : "create", id, true);
}

static int ha_preflight_form(struct lws *wsi, struct session *session, const struct form *form)
{
    return ha_fields_response(wsi, session, form, "preflight", session->resource_id, false);
}

static int ha_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *path = uri + sizeof("/api/nodes/sync-groups") - 1;
    if (!*path) {
        if (method == LWSHUMETH_GET)
            return ha_response(wsi, session, "list", 0, NULL, false);
        if (method == LWSHUMETH_POST) {
            session->resource_id = 0;
            return begin_form(wsi, session, ha_save_form);
        }
        return error_reply(wsi, session, 405, "method_not_allowed");
    }
    if (!strcmp(path, "/preflight")) {
        if (method != LWSHUMETH_POST)
            return error_reply(wsi, session, 405, "method_not_allowed");
        session->resource_id = 0;
        return begin_form(wsi, session, ha_preflight_form);
    }

    int64_t id;
    const char *rest;
    if (*path != '/' || !parse_resource_id(path + 1, &id, &rest) || id <= 0)
        return error_reply(wsi, session, 404, "not_found");
    if (!*rest) {
        if (method == LWSHUMETH_GET)
            return ha_response(wsi, session, "get", id, NULL, false);
        if (method == LWSHUMETH_DELETE)
            return ha_response(wsi, session, "delete", id, NULL, true);
        if (method == LWSHUMETH_PUT) {
            session->resource_id = id;
            return begin_form(wsi, session, ha_save_form);
        }
        return error_reply(wsi, session, 405, "method_not_allowed");
    }
    if (!strcmp(rest, "/status")) {
        if (method == LWSHUMETH_GET)
            return ha_response(wsi, session, "status", id, NULL, false);
        return error_reply(wsi, session, 405, "method_not_allowed");
    }
    if (!strcmp(rest, "/preflight")) {
        if (method != LWSHUMETH_POST)
            return error_reply(wsi, session, 405, "method_not_allowed");
        char length[16];
        if (lws_hdr_copy(wsi, length, (int)sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0 &&
            strcmp(length, "0")) {
            session->resource_id = id;
            return begin_form(wsi, session, ha_preflight_form);
        }
        return ha_response(wsi, session, "preflight", id, NULL, false);
    }
    if (!strcmp(rest, "/verify") || !strcmp(rest, "/setup") ||
        !strcmp(rest, "/push-full") || !strcmp(rest, "/apply-shared-domain")) {
        if (method != LWSHUMETH_POST)
            return error_reply(wsi, session, 405, "method_not_allowed");
        return ha_response(wsi, session, rest + 1, id, NULL, strcmp(rest, "/preflight") != 0);
    }
    return error_reply(wsi, session, 404, "not_found");
}
