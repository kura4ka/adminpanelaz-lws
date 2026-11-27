enum protocol_setup_kind { PROTOCOL_FLAG, PROTOCOL_DNS_WARP, PROTOCOL_WARP_MODE,
                           PROTOCOL_WARP_MTU, PROTOCOL_HOST, PROTOCOL_WARP_ENDPOINT };

static const struct protocol_setup_option {
    const char *key;
    enum protocol_setup_kind kind;
    bool openvpn;
} protocol_setup_options[] = {
    { "OPENVPN_HOST", PROTOCOL_HOST, true },
    { "OPENVPN_UDP_ENABLE", PROTOCOL_FLAG, true },
    { "OPENVPN_TCP_ENABLE", PROTOCOL_FLAG, true },
    { "OPENVPN_DUPLICATE", PROTOCOL_FLAG, true },
    { "OPENVPN_LOG", PROTOCOL_FLAG, true },
    { "WIREGUARD_HOST", PROTOCOL_HOST, false },
    { "ROUTE_ALL", PROTOCOL_FLAG, false },
    { "DISCORD_INCLUDE", PROTOCOL_FLAG, false },
    { "CLOUDFLARE_INCLUDE", PROTOCOL_FLAG, false },
    { "TELEGRAM_INCLUDE", PROTOCOL_FLAG, false },
    { "WHATSAPP_INCLUDE", PROTOCOL_FLAG, false },
    { "ROBLOX_INCLUDE", PROTOCOL_FLAG, false },
    { "AMAZON_INCLUDE", PROTOCOL_FLAG, false },
    { "HETZNER_INCLUDE", PROTOCOL_FLAG, false },
    { "DIGITALOCEAN_INCLUDE", PROTOCOL_FLAG, false },
    { "OVH_INCLUDE", PROTOCOL_FLAG, false },
    { "GOOGLE_INCLUDE", PROTOCOL_FLAG, false },
    { "AKAMAI_INCLUDE", PROTOCOL_FLAG, false },
    { "OPENVPN_BACKUP_TCP", PROTOCOL_FLAG, false },
    { "OPENVPN_BACKUP_UDP", PROTOCOL_FLAG, false },
    { "WIREGUARD_BACKUP", PROTOCOL_FLAG, false },
    { "ANTIZAPRET_WARP", PROTOCOL_WARP_MODE, false },
    { "VPN_WARP", PROTOCOL_WARP_MODE, false },
    { "WARP_PROTECTION", PROTOCOL_FLAG, false },
    { "WARP_ENDPOINT", PROTOCOL_WARP_ENDPOINT, false },
    { "WARP_MTU", PROTOCOL_WARP_MTU, false },
    { "DNS_WARP", PROTOCOL_DNS_WARP, false },
    { "RECONNECT_WARP", PROTOCOL_FLAG, false },
    { "SSH_PROTECTION", PROTOCOL_FLAG, false },
    { "ATTACK_PROTECTION", PROTOCOL_FLAG, false },
    { "SCAN_PROTECTION", PROTOCOL_FLAG, false },
    { "FLOOD_PROTECTION", PROTOCOL_FLAG, false },
    { "TORRENT_GUARD", PROTOCOL_FLAG, false },
    { "RESTRICT_FORWARD", PROTOCOL_FLAG, false },
    { "CLIENT_ISOLATION", PROTOCOL_FLAG, false },
    { "ANTIZAPRET_ADBLOCK", PROTOCOL_FLAG, false },
    { "VPN_ADBLOCK", PROTOCOL_FLAG, false },
    { "ALTERNATIVE_CLIENT_IP", PROTOCOL_FLAG, false },
    { "ALTERNATIVE_FAKE_IP", PROTOCOL_FLAG, false },
    { "CLEAR_HOSTS", PROTOCOL_FLAG, false },
    { "CLEAR_DNS_CACHE", PROTOCOL_FLAG, false }
};

enum {
    PROTOCOL_SETUP_OPTIONS = sizeof(protocol_setup_options) / sizeof(protocol_setup_options[0]),
    PROTOCOL_SETUP_FILE_LIMIT = 32 * 1024,
    PROTOCOL_SETUP_LINE_LIMIT = 1024,
    PROTOCOL_SETUP_TEXT_LIMIT = 254,
    PROTOCOL_SETUP_JSON_LIMIT = 4096
};

struct protocol_setup_values {
    const char *entries[PROTOCOL_SETUP_OPTIONS];
    char openvpn_host[PROTOCOL_SETUP_TEXT_LIMIT];
    char wireguard_host[PROTOCOL_SETUP_TEXT_LIMIT];
    char warp_endpoint[PROTOCOL_SETUP_TEXT_LIMIT];
    char warp_mtu[5];
};

static char *protocol_setup_trim(char *value)
{
    while (isspace((unsigned char)*value))
        ++value;
    char *last = value + strlen(value);
    while (last > value && isspace((unsigned char)last[-1]))
        *--last = '\0';
    return value;
}

static char *protocol_setup_value(char *text)
{
    text = protocol_setup_trim(text);
    if (*text == '\'' || *text == '"') {
        char *end = strchr(text + 1, *text);
        if (!end)
            return NULL;
        *end = '\0';
        char *tail = protocol_setup_trim(end + 1);
        return *tail && *tail != '#' ? NULL : text + 1;
    }
    for (char *cursor = text; *cursor; ++cursor) {
        if (*cursor == '#' && (cursor == text || isspace((unsigned char)cursor[-1]))) {
            *cursor = '\0';
            break;
        }
    }
    return protocol_setup_trim(text);
}

static const char *protocol_flag(const char *text, bool legacy_dns)
{
    char lower[6];
    size_t length = strlen(text);
    if (length >= sizeof(lower))
        return NULL;
    for (size_t i = 0; i <= length; ++i)
        lower[i] = (char)tolower((unsigned char)text[i]);
    if (!strcmp(lower, "y") || !strcmp(lower, "yes") || !strcmp(lower, "on") || !strcmp(lower, "true") ||
        !strcmp(lower, legacy_dns ? "2" : "1"))
        return "on";
    if (!strcmp(lower, "n") || !strcmp(lower, "no") || !strcmp(lower, "off") || !strcmp(lower, "false") ||
        !strcmp(lower, legacy_dns ? "1" : "0"))
        return "off";
    return NULL;
}

static const char *protocol_warp_mode(const char *text)
{
    static const char *const modes[] = {"1", "2", "3", "4"};
    if (text[0] >= '1' && text[0] <= '4' && !text[1])
        return modes[text[0] - '1'];
    const char *flag = protocol_flag(text, false);
    return flag ? modes[!strcmp(flag, "on")] : NULL;
}

static bool protocol_number_in_range(const char *text, unsigned long minimum, unsigned long maximum)
{
    size_t length = strspn(text, "0123456789");
    if (length == 0 || length > 5 || text[length])
        return false;
    unsigned long value = strtoul(text, NULL, 10);
    return value >= minimum && value <= maximum;
}

static bool protocol_host(const char *text, size_t length)
{
    if (!length || length >= PROTOCOL_SETUP_TEXT_LIMIT)
        return false;
    if (text[0] == '[' && text[length - 1] == ']')
        return length > 2 && strspn(text + 1, "0123456789ABCDEFabcdef:.") == length - 2;
    return strspn(text, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-") >= length;
}

static const char *protocol_setup_entry(struct protocol_setup_values *values,
                                        const struct protocol_setup_option *option, const char *value)
{
    if (!value || !*value)
        return NULL;
    if (option->kind == PROTOCOL_FLAG || option->kind == PROTOCOL_DNS_WARP)
        return protocol_flag(value, option->kind == PROTOCOL_DNS_WARP);
    if (option->kind == PROTOCOL_WARP_MODE)
        return protocol_warp_mode(value);
    size_t length = strlen(value);
    char *destination;
    if (option->kind == PROTOCOL_WARP_MTU) {
        if (length >= sizeof(values->warp_mtu) || !protocol_number_in_range(value, 1280, 1420))
            return NULL;
        destination = values->warp_mtu;
    } else if (option->kind == PROTOCOL_WARP_ENDPOINT) {
        const char *port = strrchr(value, ':');
        if (length >= PROTOCOL_SETUP_TEXT_LIMIT || !port || !protocol_host(value, (size_t)(port - value)) ||
            !protocol_number_in_range(port + 1, 1, 65535))
            return NULL;
        destination = values->warp_endpoint;
    } else {
        if (!protocol_host(value, length))
            return NULL;
        destination = option->openvpn ? values->openvpn_host : values->wireguard_host;
    }
    memcpy(destination, value, length + 1);
    return destination;
}

static bool protocol_option_visible(const struct protocol_setup_option *option, bool openvpn)
{
    return option->openvpn == openvpn || !strcmp(option->key, "OPENVPN_HOST");
}

static void parse_protocol_line(struct protocol_setup_values *values, char *line, bool openvpn)
{
    char *key = protocol_setup_trim(line);
    if (*key == '#')
        return;
    char *value = strchr(key, '=');
    if (!value)
        return;
    *value++ = '\0';
    key = protocol_setup_trim(key);
    for (size_t i = 0; i < PROTOCOL_SETUP_OPTIONS; ++i) {
        const struct protocol_setup_option *option = &protocol_setup_options[i];
        if (protocol_option_visible(option, openvpn) && !strcmp(key, option->key)) {
            values->entries[i] = protocol_setup_entry(values, option, protocol_setup_value(value));
            return;
        }
    }
}

static const char *read_protocol_setup(const char *path, struct protocol_setup_values *values, bool openvpn)
{
    if (!path)
        return "not_configured";
    FILE *input = NULL;
    unsigned long long size = 0;
    if (panel_settings_open_regular(NULL, path, &input, &size) != PANEL_SETTINGS_OK)
        return "unavailable";
    if (size > PROTOCOL_SETUP_FILE_LIMIT) {
        fclose(input);
        return "too_large";
    }
    char line[PROTOCOL_SETUP_LINE_LIMIT];
    size_t length = 0, consumed = 0;
    const char *state = "available";
    bool overflow = false;
    int byte;
    while ((byte = fgetc(input)) != EOF) {
        if (++consumed > PROTOCOL_SETUP_FILE_LIMIT || !byte) {
            state = byte ? "too_large" : "invalid";
            break;
        }
        if (byte == '\n') {
            line[length] = '\0';
            if (!overflow)
                parse_protocol_line(values, line, openvpn);
            length = 0;
            overflow = false;
        } else if (length < sizeof(line) - 1) {
            line[length++] = (char)byte;
        } else {
            overflow = true;
        }
    }
    if (ferror(input))
        state = "unavailable";
    if (!strcmp(state, "available") && !overflow && length) {
        line[length] = '\0';
        parse_protocol_line(values, line, openvpn);
    }
    fclose(input);
    OPENSSL_cleanse(line, sizeof(line));
    if (strcmp(state, "available"))
        memset(values, 0, sizeof(*values));
    return state;
}

static size_t write_protocol_setup(char *out, size_t capacity, const char *state,
                                   const struct protocol_setup_values *values)
{
    int used = snprintf(out, capacity, "{\"state\":\"%s\",\"values\":{", state);
    if (used < 0 || (size_t)used >= capacity)
        return 0;
    const char *separator = "";
    for (size_t i = 0; i < PROTOCOL_SETUP_OPTIONS; ++i) {
        if (!values->entries[i])
            continue;
        int written = snprintf(out + used, capacity - (size_t)used, "%s\"%s\":\"%s\"",
                               separator, protocol_setup_options[i].key, values->entries[i]);
        if (written < 0 || (size_t)written >= capacity - (size_t)used)
            return 0;
        used += written;
        separator = ",";
    }
    if (capacity - (size_t)used < 3)
        return 0;
    memcpy(out + used, "}}", 3);
    return (size_t)used + 2;
}

static bool protocol_count_connection(const struct vpn_counter *record, void *context)
{
    size_t *total = context;
    if (record->connected && record->name && record->name[0])
        ++*total;
    return true;
}

static size_t write_protocol_snapshot(char *out, size_t capacity)
{
    size_t total = 0, available = 0;
    for (size_t i = 0; i < config.openvpn_count; ++i) {
        size_t connections = 0;
        if (vpn_status_counters(config.openvpn[i], protocol_count_connection, &connections)) {
            total += connections;
            ++available;
        }
    }
    const char *state = !config.openvpn_count ? "not_configured" :
        !available ? "unavailable" : available < config.openvpn_count ? "partial" : "available";
    int written = snprintf(out, capacity,
        ",\"snapshot\":{\"state\":\"%s\",\"connections\":%zu,\"sources_configured\":%zu,\"sources_available\":%zu}}",
        state, total, config.openvpn_count, available);
    return written < 0 || (size_t)written >= capacity ? 0 : (size_t)written;
}

static int protocol_settings_request(struct lws *wsi, struct session *session, int method, bool openvpn)
{
    if (method != LWSHUMETH_GET)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (panel_settings_enabled("nodes")) {
        int64_t active, revision;
        if (panel_nodes_active(&active, &revision) != PANEL_NODES_OK)
            return error_reply(wsi, session, 503, "nodes_unavailable");
        if (active != 0)
            return reply(wsi, session, 200, "{\"state\":\"remote\",\"values\":{}}");
    }

    struct protocol_setup_values values = {0};
    const char *state = read_protocol_setup(config.antizapret_setup, &values, openvpn);
    size_t capacity = PROTOCOL_SETUP_JSON_LIMIT;
    char *json = malloc(capacity);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    size_t used = write_protocol_setup(json, PROTOCOL_SETUP_JSON_LIMIT, state, &values);
    if (openvpn && used && !write_protocol_snapshot(json + used - 1, capacity - used + 1))
        used = 0;
    if (used)
        return allocated_reply(wsi, session, 200, json);
    free(json);
    return error_reply(wsi, session, 503, "protocol_status_unavailable");
}
