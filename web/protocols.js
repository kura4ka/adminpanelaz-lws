const antiGroups = [
  ["Маршрутизация трафика", [
    ["ROUTE_ALL", "Все домены, кроме .ru"],
    ["DISCORD_INCLUDE", "Discord"], ["CLOUDFLARE_INCLUDE", "Cloudflare"],
    ["TELEGRAM_INCLUDE", "Telegram"], ["WHATSAPP_INCLUDE", "WhatsApp"], ["ROBLOX_INCLUDE", "Roblox"]
  ]],
  ["Безопасность сервера", [
    ["SSH_PROTECTION", "Защита от брутфорса SSH"], ["ATTACK_PROTECTION", "Защита от атак"],
    ["SCAN_PROTECTION", "Scan protection"], ["FLOOD_PROTECTION", "Защита от флуда"],
    ["TORRENT_GUARD", "Torrent Guard"], ["RESTRICT_FORWARD", "Ограничение форвардинга"],
    ["CLIENT_ISOLATION", "Изоляция клиентов и сервера"]
  ]],
  ["Резервные порты", [
    ["OPENVPN_BACKUP_TCP", "TCP"], ["OPENVPN_BACKUP_UDP", "UDP"], ["WIREGUARD_BACKUP", "WG/AWG 1.5"]
  ]],
  ["Cloudflare WARP", [
    ["ANTIZAPRET_WARP", "WARP для AntiZapret", "mode"], ["VPN_WARP", "WARP для VPN", "mode"],
    ["WARP_PROTECTION", "WARP protection"], ["WARP_ENDPOINT", "Свой endpoint Cloudflare WARP", "text"],
    ["WARP_MTU", "MTU WARP", "text"], ["DNS_WARP", "DNS через Cloudflare WARP"],
    ["RECONNECT_WARP", "Переподключать WARP"]
  ]],
  ["Очистка списков", [
    ["CLEAR_HOSTS", "Очистка хостов — казино, VPN и прокси"], ["CLEAR_DNS_CACHE", "Очистка DNS-кеша"]
  ]],
  ["AdBlock", [["ANTIZAPRET_ADBLOCK", "AdBlock для AntiZapret"], ["VPN_ADBLOCK", "AdBlock для VPN"]]],
  ["Адреса подключения", [
    ["OPENVPN_HOST", "OpenVPN", "text"], ["WIREGUARD_HOST", "WireGuard и AmneziaWG", "text"]
  ]],
  ["Подсети клиентов", [
    ["ALTERNATIVE_CLIENT_IP", "Подсети клиентов 172.x"], ["ALTERNATIVE_FAKE_IP", "Fake-IP 198.18"]
  ]],
  ["Другие параметры", [
    ["AMAZON_INCLUDE", "Amazon"], ["HETZNER_INCLUDE", "Hetzner"], ["DIGITALOCEAN_INCLUDE", "DigitalOcean"],
    ["OVH_INCLUDE", "OVH"], ["GOOGLE_INCLUDE", "Google"], ["AKAMAI_INCLUDE", "Akamai"]
  ]]
];
const warpModes = {
  1: "None — не использовать",
  2: "All — весь трафик",
  3: "Domain — домены AntiZapret и списка WARP",
  4: "Custom — только домены списка WARP"
};
const setupStates = {
  not_configured: "Источник конфигурации setup не настроен.",
  unavailable: "Файл setup недоступен.",
  too_large: "Файл setup превышает допустимый размер.",
  invalid: "Не удалось прочитать формат файла setup.",
  remote: "Для выбранного узла чтение конфигурации и снимков VPN пока недоступно."
};
const snapshotStates = {
  available: "Доступен", partial: "Частично доступен",
  unavailable: "Недоступен", not_configured: "Источники не настроены"
};
const countFormat = new Intl.NumberFormat("ru-RU");

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function linkedAction(label, path, context) {
  const link = node("a", "link-button", label);
  const base = document.querySelector('meta[name="apaz-base"]').content;
  link.href = base + path;
  link.addEventListener("click", (event) => {
    if (!event.button && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) {
      event.preventDefault();
      context.navigate(path);
    }
  });
  return link;
}

function showValue(value, kind = "flag") {
  if (kind === "mode") return warpModes[value] || "—";
  if (kind === "flag") return value === "on" ? "Вкл" : value === "off" ? "Выкл" : "—";
  return value || "—";
}

function card(title, rows, description) {
  const panel = node("section", "panel protocol-card");
  panel.append(node("h2", "", title));
  if (description) panel.append(node("p", "muted protocol-caption", description));
  const list = node("dl", "protocol-values");
  for (const [label, value, showKey] of rows) {
    const row = node("div");
    const labelElement = node("dt", "", label);
    if (showKey) labelElement.append(node("code", "muted", showKey));
    row.append(labelElement, node("dd", "", value));
    list.append(row);
  }
  panel.append(list);
  return panel;
}

function showAntiZapret(root, context, data) {
  if (data.state !== "available") return;
  const grid = node("div", "protocol-grid");
  for (const [group, fields] of antiGroups) {
    const panel = card(group, fields.map(([key, label, kind]) => [label, showValue(data.values[key], kind), key]));
    if (group === "Адреса подключения") {
      panel.classList.add("protocol-wide");
      if (context.features?.openvpn !== false)
        panel.append(linkedAction("Состояние OpenVPN", "/protocols/openvpn", context));
    }
    grid.append(panel);
  }
  root.append(grid);
}

function showOpenVpn(root, context, data) {
  const grid = node("div", "protocol-grid");
  if (data.state === "available") {
    const address = card("Подключение", [
      ["Адрес OpenVPN", showValue(data.values.OPENVPN_HOST, "text"), "OPENVPN_HOST"],
      ["UDP", showValue(data.values.OPENVPN_UDP_ENABLE), "OPENVPN_UDP_ENABLE"],
      ["TCP", showValue(data.values.OPENVPN_TCP_ENABLE), "OPENVPN_TCP_ENABLE"]
    ], "Параметры файла setup текущего узла.");
    grid.append(address);
  }
  if (data.snapshot) {
    const report = data.snapshot;
    const diagnostics = card("Профили, логи и состояние установки", [
      ["Снимок состояния", snapshotStates[report.state] || "—"],
      ["Доступные источники", countFormat.format(report.sources_available) + " из " + countFormat.format(report.sources_configured)],
      ["Подключения по доступным источникам", report.sources_available ? countFormat.format(report.connections) : "—"],
      ...(data.state === "available" ? [
        ["Повторные подключения с одним профилем", showValue(data.values.OPENVPN_DUPLICATE), "OPENVPN_DUPLICATE"],
        ["Логи OpenVPN", showValue(data.values.OPENVPN_LOG), "OPENVPN_LOG"]
      ] : [])
    ]);
    if (context.features?.logs_dashboard !== false)
      diagnostics.append(linkedAction("Открыть подключения", "/monitoring", context));
    grid.append(diagnostics);
  }
  root.append(grid);
}

function makeView(view, render) {
  return {
    async mount(root, context) {
      const state = node("p", "feedback", "Загрузка…");
      state.setAttribute("role", "status");
      root.append(state);
      try {
        const response = await context.api("/api/protocols/" + view);
        if (!response.ok) {
          if (response.status === 403) {
            state.textContent = "Раздел недоступен для текущих настроек или прав.";
            state.dataset.kind = "error";
            return;
          }
          throw new Error("protocol status");
        }
        const data = await response.json();
        if (context.signal.aborted) return;
        state.textContent = data.state === "available" ? "Конфигурация setup · чтение" :
          setupStates[data.state] || "Не удалось прочитать состояние.";
        render(root, context, data);
      } catch {
        if (context.signal.aborted) return;
        state.textContent = "Не удалось загрузить состояние протокола.";
        state.dataset.kind = "error";
      }
    }
  };
}

window.apazModules ??= {};
window.apazModules.antizapret = makeView("antizapret", showAntiZapret);
window.apazModules.openvpn = makeView("openvpn", showOpenVpn);
