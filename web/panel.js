"use strict";

const element = (id) => document.getElementById(id);
const setText = (id, value) => { element(id).textContent = value; };
const missing = "—";
const tokenKey = "adminpanelaz.token";
const pollInterval = 2000;
const requestTimeout = 8000;
const integer = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 0 });
const decimal = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });
const timeFormat = new Intl.DateTimeFormat("ru-RU", { timeStyle: "medium" });
const dateTimeFormat = new Intl.DateTimeFormat("ru-RU", {
  dateStyle: "short",
  timeStyle: "medium"
});
const sizeUnits = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ", "ЭиБ"];
const accessPath = document.querySelector('meta[name="apaz-base"]').content;
const views = {
  monitor: { title: "Наблюдение", panel: "dashboard", path: "/monitoring", feature: "logs_dashboard" },
  profiles: { title: "Клиенты", panel: "profiles-page", path: "/", module: "clients", mount: "clients-actions" },
  nodes: { title: "Узлы", panel: "nodes-page", path: "/nodes", module: "nodes", feature: "nodes" },
  proxy: { title: "Прокси", panel: "proxy-page", path: "/proxy", module: "nodes", feature: "proxy_nodes" },
  cidr: { title: "Маршрутизация", panel: "cidr-page", path: "/routing", module: "cidr", feature: "routing" },
  antizapret: { title: "AntiZapret", panel: "antizapret-page", path: "/protocols/antizapret", module: "protocols", feature: "antizapret_config" },
  openvpn: { title: "OpenVPN", panel: "openvpn-page", path: "/protocols/openvpn", module: "protocols", feature: "openvpn" },
  files: { title: "Редактор файлов", panel: "files-page", path: "/edit-files", module: "settings", feature: "edit_files" },
  settings: { title: "Настройки", panel: "settings-page", path: "/settings", module: "settings" },
  diagnostics: { title: "Проверка работы", panel: "diagnostics-page", path: "/settings/tests", module: "settings", feature: "diagnostics_tests" },
  backups: { title: "Резервные копии", panel: "backups-page", path: "/settings/backup", feature: "backups" },
  personal: { title: "Мой профиль", panel: "personal-page", path: "/settings/personal", module: "security", mount: "security-actions" },
  telegram: { title: "Telegram", panel: "telegram-page", path: "/telegram", module: "telegram", feature: "telegram" },
  users: { title: "Пользователи панели", panel: "users-page", path: "/settings/users", module: "users", feature: "user_management" }
};
const navButtons = document.querySelectorAll("[data-view]");
const maxBackupSize = 200 * 1024 * 1024;
let session;
let inspectionRequest = 0;
let loginController;
let loginCaptcha;

function savedToken() {
  try { return sessionStorage.getItem(tokenKey) || ""; }
  catch { return ""; }
}

function rememberToken(token) {
  try {
    if (token) sessionStorage.setItem(tokenKey, token);
    else sessionStorage.removeItem(tokenKey);
  } catch {
    // A blocked storage API still permits an in-memory session.
  }
}

function isMetric(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function count(value) {
  return isMetric(value) ? integer.format(value) : missing;
}

function bytes(value) {
  if (!isMetric(value)) return missing;
  let unit = 0;
  while (value >= 1024 && unit < sizeUnits.length - 1) {
    value /= 1024;
    unit++;
  }
  return decimal.format(value) + "\u00a0" + sizeUnits[unit];
}

function duration(value) {
  if (!isMetric(value)) return missing;
  const seconds = Math.floor(value);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor(seconds / 3600) % 24;
  const minutes = Math.floor(seconds / 60) % 60;
  if (days) return integer.format(days) + "\u00a0д " + hours + "\u00a0ч";
  if (hours) return hours + "\u00a0ч " + minutes + "\u00a0мин";
  if (minutes) return minutes + "\u00a0мин " + seconds % 60 + "\u00a0с";
  return seconds + "\u00a0с";
}

function metricText(value) {
  return typeof value === "string" && value.trim() ? value : missing;
}

function since(value) {
  if (!isMetric(value) || value === 0) return metricText(value);
  const date = new Date(value * 1000);
  return Number.isFinite(date.getTime()) ? dateTimeFormat.format(date) : missing;
}

function bar(id, percent) {
  element(id).style.width = (isMetric(percent) ? Math.min(100, percent) : 0) + "%";
}

function capacity(resource, used, total) {
  const percent = isMetric(used) && isMetric(total) && total > 0 ? used * 100 / total : null;
  setText(resource + "-value", bytes(used));
  setText(resource + "-detail", isMetric(total) ? "из " + bytes(total) : "Использовано");
  bar(resource + "-bar", percent);
}

function renderTable(table, rows, formatRow, emptyMessage, numericColumns) {
  const fragment = document.createDocumentFragment();
  for (const row of rows) {
    const record = document.createElement("tr");
    formatRow(row || {}).forEach((value, index) => {
      const cell = document.createElement("td");
      if (value instanceof Node) cell.appendChild(value);
      else cell.textContent = value;
      if (numericColumns.includes(index)) cell.className = "numeric";
      record.appendChild(cell);
    });
    fragment.appendChild(record);
  }
  element(table + "-body").replaceChildren(fragment);
  element(table + "-scroll").hidden = rows.length === 0;
  element(table + "-empty").hidden = rows.length > 0;
  setText(table + "-empty", emptyMessage);
}

function render(data) {
  const host = data?.host || {};
  const cpu = host.cpu_percent;
  setText("cpu-value", isMetric(cpu) ? decimal.format(cpu) + "\u00a0%" : missing);
  setText("cpu-detail", data && cpu === null ? "Ожидаем замер" : "Загрузка");
  bar("cpu-bar", cpu);
  capacity("memory", host.memory_used_bytes, host.memory_total_bytes);
  capacity("disk", host.disk_used_bytes, host.disk_total_bytes);
  setText("host-uptime", duration(host.uptime_seconds));
  setText("tcp", count(host.tcp_established));
  setText("process-uptime", duration(data?.uptime_seconds));
  setText("streams", count(data?.streams));
  setText("uploaded", bytes(data?.uploaded_bytes));

  const interfaces = Array.isArray(host.interfaces) ? host.interfaces : [];
  renderTable("interfaces", interfaces, (item) => [
    metricText(item.name), bytes(item.rx_bytes), bytes(item.tx_bytes)
  ], data ? "Нет данных об интерфейсах." : "Ожидаем первый ответ сервера.", [1, 2]);

  renderVpn("vpn", data?.vpn, Boolean(data));
  renderVpn("wireguard", data?.wireguard, Boolean(data));
}

function renderVpn(section, source, loaded) {
  const wireguard = section === "wireguard";
  const protocol = wireguard ? "WireGuard" : "OpenVPN";
  const available = source?.state === "available";
  const clients = available && Array.isArray(source.clients) ? source.clients : [];
  let status = "Ожидаем первый ответ сервера.";
  if (loaded) {
    if (available) {
      if (source.total === 0) {
        status = wireguard ? "Клиенты WireGuard не зарегистрированы." : "Активных подключений OpenVPN нет.";
      } else {
        status = "Данные клиентов " + protocol + " отсутствуют.";
      }
    } else if (source?.state === "not_configured") {
      status = "Источник данных о клиентах " + protocol + " не настроен.";
    } else {
      status = "Источник данных о клиентах " + protocol + " недоступен.";
    }
  }

  let summary = "";
  if (available) {
    summary = (wireguard ? "Зарегистрировано: " : "Активных: ") + count(source.total);
    if (wireguard) {
      const haveCompleteList = clients.length === source.total && clients.every((client) => typeof client?.online === "boolean");
      const active = isMetric(source.active) ? source.active :
        haveCompleteList ? clients.filter((client) => client.online).length : null;
      summary += " · Активных: " + count(active);
    }
  }
  setText(section + "-count", summary);
  renderTable(section, clients, (client) => {
    const link = document.createElement("button");
    link.type = "button";
    link.className = "link-button";
    link.textContent = metricText(client.name);
    link.addEventListener("click", () => openPath(views.monitor.path + "?" + new URLSearchParams({ tab: "traffic", client: client.name })));
    const cells = [
      client.name && session?.identity.role === "admin" && session.features?.traffic_sync !== false ? link : metricText(client.name),
      metricText(client.remote), metricText(client.virtual_ip),
      bytes(client.rx_bytes), bytes(client.tx_bytes), since(client.since)
    ];
    if (wireguard) {
      let activity = missing;
      if (client.online === true) activity = "Активен";
      if (client.online === false) activity = "Неактивен";
      cells.unshift(activity);
    }
    return cells;
  }, status, wireguard ? [4, 5] : [3, 4]);
  element(section + "-truncated").hidden = !(available && source.truncated);
  setText(section + "-truncated", "Показано " + count(clients.length) + " из " + count(source?.total) + ".");
  if (wireguard) element("wireguard-activity").hidden = !available;
}

function connectionState(state, label, error = "") {
  const status = element("connection-state");
  status.dataset.state = state;
  if (status.textContent !== label) status.textContent = label;
  element("request-error").hidden = !error;
  setText("request-error", error);
}

function notice(id, message = "", kind = "") {
  const target = element(id);
  target.dataset.kind = kind;
  target.textContent = message;
  target.hidden = !message;
}

function api(path, options = {}, active = session) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin || !url.pathname.startsWith("/api/")) {
    throw new Error("Invalid API path");
  }
  const headers = new Headers(options.headers);
  if (active?.token) headers.set("Authorization", "Bearer " + active.token);
  return fetch(accessPath + url.pathname + url.search, {
    cache: "no-store",
    credentials: active?.token ? "omit" : "same-origin",
    redirect: "error",
    signal: active?.controller.signal,
    ...options,
    headers
  });
}

function stopMonitoring(active) {
  if (!active.monitor) return;
  const monitor = active.monitor;
  active.monitor = undefined;
  clearTimeout(monitor.timer);
  monitor.controller.abort();
}

function stopView(active) {
  active.page?.abort();
  active.history?.abort();
  stopMonitoring(active);
}

function requireSession(active, response, monitorRequest = false) {
  if (active !== session) return false;
  const tokenNeedsLogin = active.token && !monitorRequest && (response.status === 401 || response.status === 403);
  if (tokenNeedsLogin) {
    authenticate();
    notice("auth-error", "Для этого раздела войдите с логином и паролем.", "error");
    element("username").focus();
    return false;
  }
  if (response.status !== 401) return true;
  const error = active.token ? "Проверьте токен доступа." : "Сессия завершилась. Войдите снова.";
  authenticate(error, "error", true);
  return false;
}

function authenticate(message = "", kind = "", focus = false) {
  const wasToken = Boolean(session?.token);
  if (session) {
    stopView(session);
    session.controller.abort();
    session = undefined;
  }
  rememberToken("");
  render(null);
  for (const { panel } of Object.values(views)) element(panel).hidden = true;
  element("connection").hidden = true;
  element("account-actions").hidden = true;
  element("site-nav").hidden = true;
  delete document.body.dataset.signedIn;
  element("checking-session").hidden = true;
  element("authentication").hidden = false;
  element("password-form").reset();
  element("upload-form").reset();
  element("password-dialog").close();
  element("login-factor").hidden = true;
  element("login-code").value = "";
  clearCaptcha();
  closeInspection();
  element("profiles-body").replaceChildren();
  element("backups-body").replaceChildren();
  element("token-access").open = Boolean(message && wasToken);
  setText("page-title", "Вход в панель");
  document.title = "Вход · AdminPanelAZ";
  notice("account-notice");
  notice("auth-error", message, kind);
  showTelegramLogin();
  if (focus) element(wasToken && kind === "error" ? "token" : "username").focus();
}

async function poll(active, monitor) {
  const controller = new AbortController();
  const signal = AbortSignal.any([controller.signal, monitor.controller.signal]);
  const started = performance.now();
  const timeout = setTimeout(() => controller.abort(), requestTimeout);
  const current = () => session === active && active.monitor === monitor;
  try {
    const response = await api("/api/monitor", { signal }, active);
    if (!current() || !requireSession(active, response, true)) return;
    if (!response.ok) throw new Error("Monitor unavailable");
    const data = await response.json();
    if (!current()) return;
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid response");

    render(data);
    connectionState("live", "Подключено");
    const observed = new Date();
    const updated = element("updated");
    updated.dateTime = observed.toISOString();
    updated.textContent = "Обновлено в " + timeFormat.format(observed);
    updated.hidden = false;
  } catch {
    if (!current()) return;
    connectionState("error", "Нет связи",
      "Не удалось получить метрики. Запрос повторится автоматически.");
  } finally {
    clearTimeout(timeout);
    if (current()) {
      const elapsed = performance.now() - started;
      monitor.timer = setTimeout(() => poll(active, monitor), Math.max(0, pollInterval - elapsed));
    }
  }
}

async function mountModule(active, resource, name, root, controller, extra = {}) {
  root.replaceChildren();
  try {
    await import(accessPath + "/assets/" + resource + ".js");
    if (controller.signal.aborted) return;
    const component = window.apazModules[name];
    await component.mount(root, {
      api: (path, options = {}) => api(path, { ...options,
        signal: options.signal ? AbortSignal.any([controller.signal, options.signal]) : controller.signal }, active),
      signal: controller.signal,
      navigate: openPath,
      identity: active.identity,
      features: active.features,
      updateFeatures: (features) => features ? updateFeatures(active, features) : loadFeatures(active),
      updateActiveNode: () => refreshActiveNode(active),
      reloadProfiles: (offset = 0, cursor = "", filter) => loadCollection(active, "profiles", offset, cursor, filter),
      filterProfiles: (filter) => loadCollection(active, "profiles", 0, "", filter),
      ...extra
    });
  } catch {
    if (!controller.signal.aborted) {
      const message = document.createElement("p");
      message.className = "notice";
      message.textContent = "Не удалось открыть раздел.";
      root.replaceChildren(message);
    }
  }
}

function allowedView(active, view) {
  if (active.identity.must_change_password) return view === "personal";
  if (active.identity.role === "user") return view === "personal" || (view === "telegram" && active.features?.telegram !== false);
  if (active.token) return view === "monitor";
  const feature = views[view].feature;
  return !feature || active.features?.[feature] !== false;
}

function showView(view) {
  const active = session;
  if (!active) return;
  if (!allowedView(active, view)) view = active.identity.role === "admin" && !active.identity.must_change_password ?
    "profiles" : active.token ? "monitor" : "personal";
  const pageKey = view === "monitor" ? view : view + location.pathname + location.search;
  if (active.pageKey === pageKey) return;
  stopView(active);
  if (active.view === "backups") closeInspection();
  active.view = view;
  active.pageKey = pageKey;
  active.page = new AbortController();
  for (const [key, { panel }] of Object.entries(views)) element(panel).hidden = key !== view;
  for (const button of navButtons) {
    const settingsPage = ["backups", "personal", "diagnostics", "users"].includes(view) && button.dataset.view === "settings";
    if (button.dataset.view === view || settingsPage) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  const { title, panel, module, mount } = views[view];
  setText("page-title", title);
  document.title = title + " · AdminPanelAZ";
  element("connection").hidden = view !== "monitor";
  if (view === "monitor") {
    element("updated").hidden = true;
    connectionState("loading", "Загрузка");
    active.monitor = { controller: new AbortController() };
    poll(active, active.monitor);
  } else if (view === "profiles" || view === "backups") {
    loadCollection(active, view);
  }
  if (module) {
    const tab = view === "settings" ? location.pathname.slice(accessPath.length).split("/")[2] : undefined;
    mountModule(active, module, view === "profiles" ? "clients" : view,
      element(mount || panel), active.page, { tab });
  }
}

async function refreshActiveNode(active) {
  if (active.identity.role !== "admin" || active.identity.must_change_password) return;
  try {
    const response = await api("/api/nodes", {}, active);
    const data = response.ok ? await response.json() : {};
    if (session !== active) return;
    const select = element("active-node-select");
    const nodes = (data.nodes || []).filter(node => node.kind === "vpn");
    const nodeId = active.features?.nodes === false ? 0 : data.active_node_id;
    const selected = nodes.find(node => node.id === nodeId);
    setText("active-node", selected?.name || "Локальный узел");
    select.replaceChildren(...nodes.map(node => new Option(node.name, node.id, node.id === nodeId, node.id === nodeId)));
    select.hidden = nodes.length < 2 || active.features?.nodes === false;
    element("active-node").hidden = !select.hidden;
    active.nodeRevision = data.revision;
  } catch { /* The local node remains the default until the next successful request. */ }
}

async function loadFeatures(active) {
  try {
    const response = await api("/api/settings/features", {}, active);
    if (!response.ok) return;
    const { features } = await response.json();
    updateFeatures(active, features);
    refreshActiveNode(active);
  } catch { /* API permission checks remain authoritative. */ }
}

function updateFeatures(active, features) {
  if (session !== active) return;
  active.features = features;
  for (const button of navButtons) {
    button.hidden = !allowedView(active, button.dataset.view) ||
      (button.dataset.view === "profiles" && features.clients_page === false);
  }
  if (active.view && !allowedView(active, active.view)) showView("profiles");
  if (active.view === "monitor") selectMonitorTab(new URLSearchParams(location.search).get("tab"));
}

function startSession(token = "", identity = { username: "admin", role: "monitor" }) {
  const active = { token, identity, controller: new AbortController() };
  session = active;
  loginController?.abort();
  rememberToken(token);
  element("authentication").hidden = true;
  element("checking-session").hidden = true;
  element("account-actions").hidden = false;
  element("show-password").hidden = Boolean(token);
  element("site-nav").hidden = false;
  for (const button of navButtons) button.hidden = !allowedView(active, button.dataset.view);
  for (const heading of document.querySelectorAll(".nav-group")) heading.hidden = identity.role !== "admin";
  document.body.dataset.signedIn = "true";
  setText("account-name", identity.username);
  setText("personal-name", identity.username);
  setText("personal-role", identity.role === "admin" ? "Администратор" : "Пользователь");
  setText("active-node", "Локальный узел");
  element("active-node").hidden = false;
  element("active-node-select").hidden = true;
  notice("account-notice");
  showView(token ? "monitor" : locationView());
  selectMonitorTab(new URLSearchParams(location.search).get("tab"));
  if (identity.must_change_password) {
    notice("account-notice", "Установите новый пароль, чтобы продолжить.", "error");
    element("show-password").click();
  } else if (identity.role === "admin") {
    loadFeatures(active);
    refreshActiveNode(active);
  }
}

element("active-node-select").addEventListener("change", async (event) => {
  const active = session;
  if (!active) return;
  const select = event.currentTarget;
  select.disabled = true;
  notice("account-notice");
  const body = new URLSearchParams({ revision: active.nodeRevision });
  try {
    const response = await api("/api/nodes/" + encodeURIComponent(select.value) + "/activate", { method: "POST", body }, active);
    if (!response.ok) throw new Error("Node activation failed");
    if (active === session && ["profiles", "antizapret", "openvpn"].includes(active.view)) {
      active.pageKey = "";
      showView(active.view);
    }
  } catch {
    if (active === session) notice("account-notice", "Выбор узла не сохранён. Проверьте его текущую группу и повторите.", "error");
  } finally {
    await refreshActiveNode(active);
    select.disabled = false;
  }
});

function rowActions(...actions) {
  const container = document.createElement("div");
  container.className = "row-actions";
  for (const [label, handler] of actions) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = label;
    button.addEventListener("click", () => handler(button));
    container.appendChild(button);
  }
  return container;
}

function downloadName(response, fallback) {
  const header = response.headers.get("Content-Disposition") || "";
  const encoded = header.match(/filename\*=(?:UTF-8'')([^;]+)/i)?.[1];
  if (encoded) {
    try { return decodeURIComponent(encoded.trim()); }
    catch { /* Use the plain filename. */ }
  }
  return header.match(/filename="([^"]+)"|filename=([^;]+)/i)?.slice(1).find(Boolean)?.trim() || fallback;
}

async function download(active, view, id, fallback, button) {
  const status = view + "-feedback";
  button.disabled = true;
  notice(status, "Подготовка файла…");
  try {
    const route = "/api/" + view + "/" + encodeURIComponent(id) + "/download";
    const response = await api(route, {}, active);
    if (!requireSession(active, response)) return;
    if (!response.ok) throw new Error("Download unavailable");
    const file = await response.blob();
    if (active !== session) return;
    const url = URL.createObjectURL(file);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = downloadName(response, fallback);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    notice(status, "Скачивание началось.", "success");
  } catch {
    if (active === session) notice(status, "Не удалось скачать файл.", "error");
  } finally {
    button.disabled = false;
  }
}

async function loadCollection(active, view, offset = 0, cursor = "", filter) {
  const profiles = view === "profiles";
  const params = new URLSearchParams();
  if (profiles) {
    if (filter) active.profileFilter = filter;
    if (active.profileFilter?.query) params.set("query", active.profileFilter.query);
    if (active.profileFilter?.protocol) params.set("protocol", active.profileFilter.protocol);
    if (offset) params.set("offset", String(offset));
    if (cursor) params.set("cursor", cursor);
  }
  const request = Symbol();
  active.listRequest = request;
  const isCurrent = () => active === session && active.view === view && active.listRequest === request;
  const status = view + "-feedback";
  const loading = profiles ? "Загрузка профилей…" : "Загрузка резервных копий…";
  notice(status);
  renderTable(view, [], () => [], loading, []);
  try {
    const response = await api("/api/" + view + (params.size ? "?" + params : ""), { signal: active.page.signal }, active);
    if (!isCurrent() || !requireSession(active, response)) return;
    if (!response.ok) throw new Error("List unavailable");
    const data = await response.json();
    if (!isCurrent()) return;
    const list = profiles ? data.profiles : data.archives;
    const rows = Array.isArray(list) ? list : [];
    let empty = profiles ? "VPN-профилей нет." : "Резервных копий нет.";
    if (profiles && data.state === "unavailable") empty = "Каталог VPN-профилей недоступен.";
    if (profiles && data.state === "remote") empty = "Каталог профилей удалённого узла пока недоступен.";
    if (profiles) {
      const { offset, next_offset, next_cursor } = data;
      renderProfiles(rows, empty);
      element("clients-actions").dispatchEvent(new CustomEvent("apaz:profile-page", { detail: { offset, next_offset, next_cursor } }));
    } else {
      renderTable(view, rows, (item) => {
        const name = metricText(item.name);
        return [name, since(item.mtime), bytes(item.size_bytes), typeof item.name === "string" ? rowActions(
          ["Содержимое", () => inspect(active, item.name)],
          ["Скачать", (button) => download(active, view, item.name, name, button)],
          ["Удалить", (button) => removeBackup(active, item.name, button)]) : missing];
      }, empty, [2]);
    }
    if (data.truncated && !profiles) notice(status, "Показано " + count(rows.length) + ". Список ограничен сервером.");
  } catch {
    if (isCurrent()) setText(view + "-empty", "Не удалось загрузить список. Откройте раздел снова.");
  }
}

function renderProfiles(rows, empty) {
  const active = session;
  renderTable("profiles", rows, (item) => {
    const name = metricText(item.name);
    return [name, metricText(item.protocol), metricText(item.variant), bytes(item.size_bytes),
      typeof item.id === "string" ? rowActions(["Скачать", (button) => download(active, "profiles", item.id, name, button)]) : missing];
  }, empty, [3]);
}

async function removeBackup(active, name, button) {
  if (!confirm("Удалить резервную копию «" + name + "»?")) return;
  button.disabled = true;
  try {
    const response = await api("/api/backups/" + encodeURIComponent(name), { method: "DELETE" }, active);
    if (!requireSession(active, response)) return;
    if (!response.ok) throw new Error("Backup removal failed");
    closeInspection();
    await loadCollection(active, "backups");
    if (active === session && active.view === "backups") notice("backups-feedback", "Копия удалена.", "success");
  } catch {
    if (active === session && active.view === "backups") notice("backups-feedback", "Не удалось удалить копию.", "error");
  } finally {
    button.disabled = false;
  }
}

function closeInspection() {
  inspectionRequest++;
  element("inspection").hidden = true;
  setText("inspection-name", "");
  setText("inspection-state", "");
  element("inspection-components").replaceChildren();
  element("inspection-components").hidden = true;
}

async function inspect(active, name) {
  closeInspection();
  const request = inspectionRequest;
  const current = () => active === session && request === inspectionRequest;
  const panel = element("inspection");
  panel.hidden = false;
  setText("inspection-name", name);
  setText("inspection-state", "Читаем архив…");
  panel.scrollIntoView({ block: "nearest" });
  try {
    const route = "/api/backups/" + encodeURIComponent(name) + "/inspect";
    const response = await api(route, {}, active);
    if (!current() || !requireSession(active, response)) return;
    if (!response.ok) throw new Error("Inspection unavailable");
    const data = await response.json();
    if (!current()) return;
    const states = {
      unavailable: "Проверка архива недоступна.",
      invalid: "Формат архива не распознан или файл повреждён.",
      limit_exceeded: "Архив превышает предел проверки."
    };
    if (data.state !== "available") {
      setText("inspection-state", states[data.state] || states.unavailable);
      return;
    }
    const format = metricText(data.format);
    const suffix = data.encrypted ? " · Зашифрован" : "";
    setText("inspection-state", format + suffix);
    const list = element("inspection-components");
    const components = {
      db: "База данных панели",
      cidr_db: "База данных CIDR",
      env: "Переменные окружения",
      configs: "Списки и конфигурации AntiZapret",
      awg2: "Архив слоя AmneziaWG 2.0",
      lws_auth: "База учётных записей AdminPanelAZ LWS"
    };
    for (const item of Array.isArray(data.components) ? data.components : []) {
      const li = document.createElement("li");
      li.textContent = Object.hasOwn(components, item) ? components[item] : metricText(item);
      list.appendChild(li);
    }
    list.hidden = list.childElementCount === 0;
  } catch {
    if (current()) setText("inspection-state", "Не удалось прочитать содержимое архива.");
  }
}

function clearCaptcha() {
  loginCaptcha = undefined;
  element("login-captcha").hidden = true;
  element("captcha-image").removeAttribute("src");
  element("captcha-answer").value = "";
  element("captcha-answer").required = false;
}

async function refreshCaptcha(focus) {
  loginCaptcha = undefined;
  element("captcha-answer").value = "";
  element("captcha-image").removeAttribute("src");
  element("login-captcha").hidden = false;
  try {
    const response = await api("/api/auth/captcha", { signal: AbortSignal.timeout(requestTimeout) });
    if (!response.ok || session) return;
    const challenge = await response.json();
    if (!/^[0-9a-f]{32}$/i.test(challenge.id) || !/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(challenge.image))
      throw new Error("Invalid captcha");
    loginCaptcha = challenge.id;
    element("captcha-image").src = challenge.image;
    element("captcha-answer").required = true;
    if (focus) element("captcha-answer").focus();
  } catch {
    if (!session) notice("auth-error", "Не удалось загрузить проверочный код.", "error");
  }
}

async function showTelegramLogin() {
  loginController?.abort();
  loginController = new AbortController();
  const { signal } = loginController;
  const root = element("telegram-login");
  root.replaceChildren();
  try {
    await import(accessPath + "/assets/telegram.js");
    if (signal.aborted) return;
    await window.apazModules.telegram.mountLogin(root, {
      api: (path, options = {}) => api(path, { ...options, signal }), signal,
      onLogin: (identity) => { if (!signal.aborted) startSession("", identity); }
    });
  } catch { /* Password and token access remain available. */ }
}

element("captcha-refresh").addEventListener("click", () => refreshCaptcha(true));

element("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = element("login-submit");
  button.disabled = true;
  notice("auth-error");
  const password = element("password");
  const code = element("login-code");
  const body = new URLSearchParams({ username: element("username").value.trim(), password: password.value });
  const hadChallenge = Boolean(loginCaptcha);
  if (hadChallenge) {
    body.set("captcha_id", loginCaptcha);
    body.set("captcha_answer", element("captcha-answer").value.trim());
  }
  if (!element("login-factor").hidden && code.value.trim()) body.set("code", code.value.trim());
  code.value = "";
  try {
    const response = await api("/api/auth/login", { method: "POST", body });
    const data = await response.json();
    if (response.ok) {
      password.value = "";
      element("login-factor").hidden = true;
      clearCaptcha();
      startSession("", data);
    } else if (data.error === "captcha_required") {
      notice("auth-error", "Введите символы с изображения и повторите вход.", "error");
      await refreshCaptcha(true);
    } else if (data.error === "second_factor_required") {
      element("login-factor").hidden = false;
      notice("auth-error", "Введите действующий код приложения или резервный код.", "error");
      if (hadChallenge) await refreshCaptcha(true);
      else code.focus();
    } else if (response.status === 429) {
      password.value = "";
      notice("auth-error", "Слишком много попыток. Попробуйте позже.", "error");
    } else if (response.status === 401 || response.status === 403) {
      password.value = "";
      notice("auth-error", "Проверьте логин и пароль.", "error");
      if (hadChallenge) await refreshCaptcha(false);
      password.focus();
    } else {
      notice("auth-error", "Вход по паролю недоступен.", "error");
    }
  } catch {
    notice("auth-error", "Не удалось связаться с сервером.", "error");
  } finally {
    button.disabled = false;
  }
});

element("token-login").addEventListener("submit", (event) => {
  event.preventDefault();
  if (element("login-submit").disabled) return;
  const input = element("token");
  const token = input.value.trim();
  if (!token) {
    notice("auth-error", "Введите токен доступа.", "error");
    input.focus();
    return;
  }
  input.value = "";
  startSession(token);
});

element("logout").addEventListener("click", async (event) => {
  const active = session;
  const button = event.currentTarget;
  if (!active) return;
  if (active.token) {
    authenticate("", "", true);
    return;
  }
  button.disabled = true;
  notice("account-notice");
  try {
    const response = await api("/api/auth/logout", { method: "POST" }, active);
    if (active !== session) return;
    if (!response.ok && response.status !== 401) throw new Error("Logout failed");
    authenticate("", "", true);
  } catch {
    if (active === session) notice("account-notice", "Не удалось завершить сессию. Попробуйте ещё раз.", "error");
  } finally {
    button.disabled = false;
  }
});

const passwordDialog = element("password-dialog");
const passwordForm = element("password-form");
element("show-password").addEventListener("click", () => {
  passwordForm.reset();
  notice("password-feedback");
  passwordDialog.showModal();
});
element("personal-password").addEventListener("click", () => element("show-password").click());
element("password-cancel").addEventListener("click", () => passwordDialog.close());
passwordDialog.addEventListener("close", () => passwordForm.reset());
passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const active = session;
  const button = element("password-submit");
  button.disabled = true;
  notice("password-feedback");
  const body = new URLSearchParams({
    old_password: element("old-password").value,
    new_password: element("new-password").value
  });
  try {
    const response = await api("/api/auth/change-password", { method: "POST", body }, active);
    if (active !== session) return;
    if (response.ok) {
      authenticate("Пароль изменён. Войдите с новым паролем.", "success", true);
    } else {
      notice("password-feedback", "Не удалось сменить пароль. Проверьте текущий пароль и требования к новому.", "error");
    }
  } catch {
    if (active === session) notice("password-feedback", "Не удалось связаться с сервером.", "error");
  } finally {
    button.disabled = false;
  }
});

async function saveBackup(action, options, messages) {
  const active = session;
  const status = "backups-feedback";
  if (!active || active.backupPending) return;
  active.backupPending = true;
  for (const id of ["upload-submit", "backup-file", "create-backup"]) element(id).disabled = true;
  notice(status, messages.pending);
  try {
    const response = await api("/api/backups/" + action, { method: "POST", ...options }, active);
    if (!requireSession(active, response)) return;
    if (!response.ok) throw new Error("Backup request failed");
    if (action === "upload") element("backup-file").value = "";
    if (active.view === "backups") await loadCollection(active, "backups");
    if (active === session) notice(status, messages.success, "success");
  } catch {
    if (active === session) notice(status, messages.error, "error");
  } finally {
    active.backupPending = false;
    if (!session?.backupPending) {
      for (const id of ["upload-submit", "backup-file", "create-backup"]) element(id).disabled = false;
    }
  }
}

element("upload-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const file = element("backup-file").files[0];
  if (!file || !file.size || file.size > maxBackupSize) {
    notice("backups-feedback", "Выберите непустой файл размером до 200 МиБ.", "error");
    return;
  }
  saveBackup("upload", { headers: { "Content-Type": "application/octet-stream" }, body: file }, {
    pending: "Загрузка файла…",
    success: "Резервная копия загружена.",
    error: "Не удалось загрузить резервную копию."
  });
});

element("create-backup").addEventListener("click", () => {
  saveBackup("create", {}, {
    pending: "Создание резервной копии…",
    success: "Резервная копия создана.",
    error: "Не удалось создать резервную копию."
  });
});

element("close-inspection").addEventListener("click", closeInspection);
const monitorButtons = document.querySelectorAll("[data-monitor-view]");
const monitorSections = document.querySelectorAll("[data-monitor-section]");

function locationView() {
  const path = location.pathname.slice(accessPath.length).replace(/\/$/, "") || "/";
  if (path === "/settings/backups") return "backups";
  if (path === "/settings/health") return "diagnostics";
  if (path === "/settings/modules") return "settings";
  if (path === "/antizapret") return new URLSearchParams(location.search).get("tab") === "openvpn-panel" ? "openvpn" : "antizapret";
  return Object.keys(views).find(view => views[view].path === path) || "profiles";
}

function selectMonitorTab(tab) {
  const features = session?.features;
  const hidden = (key) => (key === "resources" && features?.server_monitor === false) ||
    (key === "traffic" && (features?.traffic_sync === false || session?.token)) ||
    (key === "logs" && (features?.action_logs === false || session?.token));
  const selected = !hidden(tab) && Array.from(monitorButtons).some(item => item.dataset.monitorView === tab) ? tab : "connections";
  for (const item of monitorButtons) {
    item.hidden = hidden(item.dataset.monitorView);
    item.setAttribute("aria-pressed", String(item.dataset.monitorView === selected));
  }
  for (const section of monitorSections) section.hidden = !section.dataset.monitorSection.split(" ").includes(selected);
  if (session?.view !== "monitor") return;
  session.history?.abort();
  const historyTab = selected === "traffic" || selected === "logs" ||
    (selected === "resources" && features?.panel_resource_metrics !== false) ||
    (selected === "connections" && features?.connection_history !== false);
  element("history-page").hidden = !historyTab || Boolean(session.token);
  if (!element("history-page").hidden) {
    session.history = new AbortController();
    mountModule(session, "history", "history", element("history-page"), session.history, { tab: selected });
  }
}

function navigate(path) {
  if (!path.startsWith("/") || path.startsWith("//")) return;
  const target = accessPath + path;
  if (location.pathname + location.search !== target) history.pushState(null, "", target);
}

function openPath(path) {
  navigate(path);
  showView(locationView());
  selectMonitorTab(new URLSearchParams(location.search).get("tab"));
}

for (const button of navButtons) button.addEventListener("click", () => {
  const view = button.dataset.view;
  openPath(views[view].path);
});
for (const button of monitorButtons) button.addEventListener("click", () => {
  const selected = button.dataset.monitorView;
  navigate(views.monitor.path + (selected === "connections" ? "" : "?tab=" + selected));
  selectMonitorTab(selected);
});
addEventListener("popstate", () => {
  if (!session) return;
  showView(locationView());
  selectMonitorTab(new URLSearchParams(location.search).get("tab"));
});

async function initialize() {
  element("checking-session").hidden = false;
  try {
    const response = await api("/api/auth/me", { signal: AbortSignal.timeout(requestTimeout) });
    if (response.ok) {
      startSession("", await response.json());
      return;
    }
  } catch {
    // Login remains available when the session check fails.
  }
  const token = savedToken();
  if (token) startSession(token);
  else authenticate();
}

function applyTheme(light) {
  document.documentElement.dataset.theme = light ? "light" : "dark";
  const button = element("change-theme");
  button.textContent = light ? "Тёмная тема" : "Светлая тема";
  button.setAttribute("aria-pressed", String(light));
}

try { applyTheme(localStorage.getItem("adminpanelaz.theme") === "light"); } catch { applyTheme(false); }
element("change-theme").addEventListener("click", () => {
  const light = document.documentElement.dataset.theme !== "light";
  applyTheme(light);
  try { localStorage.setItem("adminpanelaz.theme", light ? "light" : "dark"); } catch { /* The theme remains active in this tab. */ }
});

initialize();
