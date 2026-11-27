const nodePath = "/api/nodes";
const haPath = nodePath + "/sync-groups";
const transportNames = { local: "Локальный", http: "HTTP", https: "HTTPS", mtls: "HTTPS + mTLS" };
const healthNames = {
  available: "В сети",
  unknown: "Неизвестно",
  invalid_config: "Проверьте параметры подключения",
  auth_failed: "Агент отклонил ключ",
  timeout: "Агент не ответил вовремя",
  tls_failed: "Не удалось проверить сертификат агента",
  response_too_large: "Слишком большой ответ агента",
  unexpected_response: "Неожиданный ответ агента",
  unavailable: "Агент недоступен"
};

function create(tag, className, label) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (label) element.textContent = label;
  return element;
}

function button(label, action, className = "secondary") {
  const control = create("button", className, label);
  control.type = "button";
  if (action) control.addEventListener("click", () => action(control));
  return control;
}

function feedback() {
  const element = create("p", "feedback");
  element.setAttribute("role", "status");
  element.hidden = true;
  return element;
}

function report(target, message = "", kind = "") {
  target.textContent = message;
  target.dataset.kind = kind;
  target.hidden = !message;
}

async function perform(context, control, target, action) {
  if (context.signal.aborted) return;
  control.disabled = true;
  report(target, "Выполняется…");
  try {
    const message = await action();
    report(target, message || "", "success");
  } catch (error) {
    if (!context.signal.aborted)
      report(target, error instanceof TypeError ? "Нет связи с панелью." : error.message, "error");
  } finally {
    control.disabled = false;
  }
}

function requestError(status, payload) {
  if (typeof payload?.data?.detail === "string") return payload.data.detail;
  if (payload?.state && healthNames[payload.state]) return healthNames[payload.state];
  if (typeof payload?.detail === "string") return payload.detail;
  if (payload?.error === "module_disabled") return "Модуль отключён в настройках.";
  switch (status) {
    case 400: return "Проверьте заполненные поля и ответ агента.";
    case 401:
    case 403: return "Для этого действия нужен доступ администратора.";
    case 404: return "Запись была удалена. Обновите список.";
    case 409: return "Действие конфликтует с текущим состоянием. Обновите список узлов.";
    case 501: return "Эта операция пока недоступна.";
    case 503: return "Агент занят или недоступен. Повторите действие после проверки.";
    default: return "Не удалось выполнить операцию.";
  }
}

async function request(context, path, method = "GET", fields) {
  const response = await context.api(path, { method, body: fields ? new URLSearchParams(fields) : undefined });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(requestError(response.status, payload));
  return payload;
}

async function agentRequest(context, path, method, fields) {
  const payload = await request(context, path, method, fields);
  if (payload?.state !== "available") throw new Error(requestError(payload?.http_status, payload));
  return payload.data;
}

function nodeRoute(id, suffix = "") {
  return nodePath + "/" + Number(id) + suffix;
}

function statusPill(node) {
  const available = node.health === "available";
  const unknown = node.health === "unknown";
  const status = create("span", "pill", available ? "В сети" : unknown ? "Неизвестно" : "Офлайн");
  status.dataset.state = available ? "live" : unknown ? "" : "error";
  status.title = healthNames[node.health] || "";
  return status;
}

function summaryCard(label, value) {
  const card = create("div", "panel resource");
  card.append(create("p", "resource-label", label), create("strong", "resource-value", String(value)));
  return card;
}

function field(form, name, caption, options = {}) {
  const label = create("label");
  const control = create(options.choices ? "select" : "input");
  control.name = name;
  if (options.choices) {
    for (const [choice, text] of options.choices) {
      const option = create("option", "", text);
      option.value = choice;
      control.append(option);
    }
    control.multiple = Boolean(options.multiple);
    control.size = options.multiple ? Math.min(5, options.choices.length || 2) : 1;
  } else {
    control.type = options.type || "text";
    if (options.maxLength) control.maxLength = options.maxLength;
    if (options.placeholder) control.placeholder = options.placeholder;
    if (options.autocomplete) control.autocomplete = options.autocomplete;
    control.spellcheck = false;
    control.autocapitalize = "off";
  }
  if (options.value !== undefined && options.value !== null) {
    if (control.multiple) {
      const selected = new Set(options.value.map(String));
      for (const option of control.options) option.selected = selected.has(option.value);
    } else {
      control.value = options.value;
    }
  }
  control.required = Boolean(options.required);
  label.append(document.createTextNode(caption + " "), control);
  form.append(label);
  return { label, control };
}

function makeDialog(root, title, signal) {
  const dialog = create("dialog", "panel authentication nodes-dialog");
  const form = create("form");
  form.append(create("h2", "", title));
  dialog.setAttribute("aria-label", title);
  dialog.append(form);
  root.append(dialog);
  const close = () => dialog.close();
  const remove = () => {
    signal.removeEventListener("abort", close);
    dialog.remove();
  };
  signal.addEventListener("abort", close, { once: true });
  dialog.addEventListener("close", remove, { once: true });
  return { dialog, form };
}

function dialogActions(dialog, form, operation) {
  const controls = create("div", "form-actions");
  const save = button(operation, null, "primary");
  save.type = "submit";
  controls.append(save, button("Отмена", () => dialog.close()));
  form.append(controls);
  return { controls, save };
}

function editNode(root, context, nodes, node, reload) {
  const { dialog, form } = makeDialog(root, node ? "Редактировать узел" : "Добавить узел", context.signal);
  field(form, "name", "Название", { value: node?.name, required: true, maxLength: 96 });
  const kinds = [["vpn", "VPN"]];
  if (context.features?.proxy_nodes !== false || node?.kind === "proxy") kinds.push(["proxy", "Прокси"]);
  const kind = field(form, "kind", "Тип узла", {
    choices: kinds, value: node?.kind || "vpn"
  }).control;
  kind.disabled = Boolean(node);
  const transport = field(form, "transport", "Способ связи", {
    choices: [["http", "HTTP"], ["https", "HTTPS"], ["mtls", "HTTPS + mTLS"]], value: node?.transport || "http"
  }).control;
  const endpoint = field(form, "endpoint", "Адрес агента", { value: node?.endpoint, required: true, maxLength: 320 }).control;
  const key = field(form, "node_key", "API-ключ агента", {
    type: "password", autocomplete: "new-password", required: !node, maxLength: 512
  }).control;
  if (node) form.append(create("p", "muted", "Укажите ключ заново, если меняете адрес агента."));
  const tls = create("div");
  const ca = field(tls, "ca_file", "Имя файла CA", { value: node?.ca_file, maxLength: 96 });
  const cert = field(tls, "client_cert", "Имя файла сертификата панели", { value: node?.client_cert, maxLength: 96 });
  const privateKey = field(tls, "client_key", "Имя файла закрытого ключа панели",
    { value: node?.client_key, maxLength: 96 });
  tls.append(create("p", "muted", "PEM-файлы должны быть установлены в каталоге node-tls сервиса."));
  form.append(tls);
  const linked = field(form, "linked_vpn_node_id", "Связанный VPN-узел", {
    choices: [["", "Без привязки"], ...nodes.filter((item) => item.kind === "vpn")
      .map((item) => [item.id, item.name])],
    value: node?.linked_vpn_node_id
  });

  function updateInputs() {
    const usesTls = transport.value !== "http";
    const usesMtls = transport.value === "mtls";
    tls.hidden = !usesTls;
    ca.control.disabled = !usesTls;
    ca.control.required = usesMtls;
    for (const { label, control } of [cert, privateKey]) {
      label.hidden = !usesMtls;
      control.disabled = !usesMtls;
      control.required = usesMtls;
    }
    linked.label.hidden = kind.value !== "proxy";
    linked.control.disabled = linked.label.hidden;
    const port = kind.value === "proxy" ? 9101 : 9100;
    endpoint.placeholder = (usesTls ? "https://" : "http://") + "agent.example:" + port;
    key.required = !node || node.endpoint !== endpoint.value.trim().replace(/\/$/, "");
  }

  kind.addEventListener("change", updateInputs);
  transport.addEventListener("change", updateInputs);
  endpoint.addEventListener("input", updateInputs);
  updateInputs();
  const target = feedback();
  form.append(target);
  const { save } = dialogActions(dialog, form, "Сохранить");
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    perform(context, save, target, async () => {
      const data = new FormData(form);
      data.set("name", String(data.get("name")).trim());
      data.set("endpoint", endpoint.value.trim());
      data.set("kind", kind.value);
      if (!data.get("linked_vpn_node_id")) data.delete("linked_vpn_node_id");
      await request(context, node ? nodeRoute(node.id) : nodePath, node ? "PUT" : "POST", data);
      await reload();
      dialog.close();
    });
  });
  dialog.showModal();
}

function confirmRemoval(root, context, title, label, operation) {
  const { dialog, form } = makeDialog(root, title, context.signal);
  form.append(create("p", "muted", label));
  const target = feedback();
  form.append(target);
  const { save } = dialogActions(dialog, form, "Удалить");
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    perform(context, save, target, async () => {
      await operation();
      dialog.close();
    });
  });
  dialog.showModal();
}

function mountNodes(root, context) {
  const header = create("div", "section-heading");
  const description = create("p", "muted", "VPN-узлы и прокси-узлы с агентами AdminPanelAZ.");
  const controls = create("div", "row-actions");
  const globalFeedback = feedback();
  const totals = create("div", "resources nodes-metrics");
  const haRoot = create("div", "panel inspection");
  const list = create("section", "panel inspection");
  const heading = create("div", "section-heading");
  const tabs = create("div", "subnav");
  tabs.setAttribute("aria-label", "Фильтр узлов по состоянию");
  const cards = create("div");
  const filters = [["all", "Все"], ["available", "В сети"], ["offline", "Офлайн"], ["unknown", "Неизвестно"]];
  let selectedFilter = "all";
  let nodes = [];
  let revision = 0;
  let activeId = 0;
  const healthReports = new Map();

  function selectedNodes() {
    if (selectedFilter === "all") return nodes;
    if (selectedFilter === "offline")
      return nodes.filter((node) => node.health !== "unknown" && node.health !== "available");
    return nodes.filter((node) => node.health === selectedFilter);
  }

  function render() {
    const online = nodes.filter((node) => node.health === "available").length;
    const offline = nodes.filter((node) => node.health !== "available" && node.health !== "unknown").length;
    totals.replaceChildren(summaryCard("Всего", nodes.length), summaryCard("В сети", online),
      summaryCard("Офлайн", offline), summaryCard("Активный", nodes.find((node) => node.id === activeId)?.name || "—"));
    for (const control of tabs.querySelectorAll("button"))
      control.setAttribute("aria-pressed", String(control.dataset.filter === selectedFilter));
    const visible = selectedNodes();
    cards.replaceChildren(...visible.map(nodeCard));
    if (!visible.length) cards.append(create("p", "empty", "Узлы с таким состоянием отсутствуют."));
  }

  async function reload() {
    const data = await request(context, nodePath);
    nodes = data.nodes;
    revision = data.revision;
    activeId = data.active_node_id;
    render();
  }

  function nodeCard(node) {
    const card = create("article", "panel upload-panel");
    const top = create("div", "section-heading");
    const title = create("h2", "", node.name);
    top.append(title, statusPill(node));
    const kind = node.kind === "proxy" ? "Прокси" : "VPN";
    const labels = [kind, transportNames[node.transport], node.active ? "Активный" : ""];
    card.append(top, create("p", "muted", labels.filter(Boolean).join(" · ")));
    if (node.endpoint) card.append(create("p", "muted", node.endpoint));
    if (node.agent_version) card.append(create("p", "muted", "Агент " + node.agent_version));
    if (node.antizapret_version) card.append(create("p", "muted", "AntiZapret " + node.antizapret_version));
    if (node.linked_vpn_node_id !== null && node.linked_vpn_node_id !== undefined) {
      const linked = nodes.find((item) => item.id === node.linked_vpn_node_id);
      if (linked) card.append(create("p", "muted", "Связанный VPN-узел — " + linked.name));
    }
    const actions = create("div", "row-actions");
    const target = feedback();
    if (healthReports.has(node.id)) report(target, ...healthReports.get(node.id));
    if (node.id !== 0) {
      actions.append(button("Здоровье", (control) => perform(context, control, target, async () => {
        try {
          const result = await request(context, nodeRoute(node.id, "/health"), "POST");
          healthReports.set(node.id, [healthNames[result?.state] || "Проверка завершена.",
            result?.state === "available" ? "success" : "error"]);
        } catch (error) {
          healthReports.set(node.id, [error.message, "error"]);
        }
        await reload();
      })));
      actions.append(button("Изменить", () => editNode(root, context, nodes, node, reload)));
      actions.append(button("Удалить", () => confirmRemoval(root, context, "Удалить узел", node.name, async () => {
        await request(context, nodeRoute(node.id), "DELETE");
        healthReports.delete(node.id);
        await reload();
        await context.updateActiveNode();
      })));
    }
    if (node.kind === "vpn" && !node.active) {
      actions.append(button("Активировать", (control) => perform(context, control, globalFeedback, async () => {
        await request(context, nodeRoute(node.id, "/activate"), "POST", { revision });
        await reload();
        await context.updateActiveNode();
        return "Активный узел изменён.";
      })));
    }
    if (node.kind === "proxy" && context.features?.proxy_nodes !== false)
      actions.append(button("Прокси", () => context.navigate("/proxy")));
    card.append(actions, target);
    return card;
  }

  for (const [value, label] of filters) {
    const control = button(label, () => {
      selectedFilter = value;
      render();
    });
    control.dataset.filter = value;
    tabs.append(control);
  }
  controls.append(button("Обновить", (control) =>
    perform(context, control, globalFeedback, reload)), button("Добавить узел", () =>
    editNode(root, context, nodes, null, reload), "primary"));
  header.append(description, controls);
  heading.append(create("h2", "", "Список узлов"), tabs);
  list.append(heading, cards);
  root.append(header, globalFeedback, totals, haRoot, list);
  report(globalFeedback, "Загрузка узлов…");
  return reload().then(() => {
    report(globalFeedback);
    mountHa(haRoot, root, context, () => nodes);
  }).catch((error) => {
    if (!context.signal.aborted) report(globalFeedback, error.message, "error");
  });
}

function addressPort(address, port) {
  return address ? String(address) + (port ? ":" + port : "") : "—";
}

function mappingsTable(mappings) {
  if (!Array.isArray(mappings) || !mappings.length)
    return create("p", "muted", "Активные соответствия не найдены.");
  const scroll = create("div", "table-scroll");
  scroll.tabIndex = 0;
  scroll.setAttribute("aria-label", "Подключения прокси");
  const table = create("table", "collection-table");
  const header = table.createTHead().insertRow();
  for (const name of ["Клиент", "Порт прокси", "Назначение"]) {
    const cell = create("th", "", name);
    cell.scope = "col";
    header.append(cell);
  }
  const body = table.createTBody();
  for (const mapping of mappings) {
    const row = body.insertRow();
    for (const value of [addressPort(mapping.client_ip, mapping.client_port), mapping.proxy_sport || "—",
      addressPort(mapping.dest_ip, mapping.dest_port)]) {
      row.insertCell().textContent = value;
    }
  }
  scroll.append(table);
  return scroll;
}

function mountProxy(root, context) {
  const header = create("div", "section-heading");
  const actions = create("div", "row-actions");
  const target = feedback();
  const cards = create("div");
  actions.append(button("Обновить", (control) => perform(context, control, target, reload)),
    button("Узлы", () => context.navigate("/nodes")));
  header.append(create("h2", "", "Прокси-узлы"), actions);
  root.append(header, target, cards);

  function proxyCard(node, nodes) {
    const card = create("article", "panel upload-panel");
    const heading = create("div", "section-heading");
    heading.append(create("h2", "", node.name), statusPill(node));
    const status = create("p", "muted", "Статус переадресации — ожидает проверки.");
    const details = feedback();
    const mappings = create("div");
    const operations = create("div", "row-actions");
    const path = nodeRoute(node.id, "/proxy");
    let currentDestination = "";

    function applyStatus(data) {
      currentDestination = data?.destination_ip || "";
      status.textContent = currentDestination ? "DESTINATION — " + currentDestination :
        data?.installed ? "Правила установлены" : "Правила переадресации не найдены";
    }

    const check = button("Проверить статус", (control) => perform(context, control, details, async () => {
      const status = await agentRequest(context, path + "/status");
      applyStatus(status);
      return status?.detail || "Статус обновлён.";
    }));
    const destination = button("Изменить DESTINATION", () => {
      const { dialog, form } = makeDialog(root, "Изменить DESTINATION", context.signal);
      const input = field(form, "destination_ip", "IPv4-адрес назначения", {
        value: currentDestination, required: true, maxLength: 15, placeholder: "192.0.2.10"
      }).control;
      input.inputMode = "decimal";
      input.pattern = "[0-9]{1,3}(\\.[0-9]{1,3}){3}";
      const resultNotice = feedback();
      form.append(resultNotice);
      const { save } = dialogActions(dialog, form, "Применить");
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        perform(context, save, resultNotice, async () => {
          const status = await agentRequest(context, path + "/destination", "PUT", { destination_ip: input.value });
          applyStatus(status);
          report(details, "Адрес назначения обновлён.", "success");
          dialog.close();
        });
      });
      dialog.showModal();
    });
    operations.append(check, destination, button("Подключения", (control) =>
      perform(context, control, details, async () => {
        const result = await agentRequest(context, path + "/mappings");
        mappings.replaceChildren(mappingsTable(result?.mappings));
        return "Список обновлён.";
      })));
    card.append(heading, create("p", "muted", node.endpoint));
    const linked = nodes.find((item) => item.id === node.linked_vpn_node_id);
    if (linked) card.append(create("p", "muted", "Связанный VPN-узел — " + linked.name));
    card.append(status, operations, details, mappings);
    return card;
  }

  async function reload() {
    const { nodes } = await request(context, nodePath);
    const proxies = nodes.filter((node) => node.kind === "proxy");
    cards.replaceChildren(...proxies.map((node) => proxyCard(node, nodes)));
    if (!proxies.length) cards.append(create("p", "empty", "Добавьте узел типа «Прокси» в разделе «Узлы»."));
  }

  report(target, "Загрузка прокси-узлов…");
  return reload().then(() => report(target)).catch((error) => {
    if (!context.signal.aborted) report(target, error.message, "error");
  });
}

function mountHa(section, root, context, getNodes) {
  const heading = create("div", "section-heading");
  const target = feedback();
  const cards = create("div");
  const add = button("Создать группу", () => editGroup(null), "primary");
  heading.append(create("h2", "", "HA · синхронизация"), add);
  section.append(heading, target, cards);

  function editGroup(group) {
    const vpnNodes = getNodes().filter((node) => node.id > 0 && node.kind === "vpn");
    const choices = vpnNodes.map((node) => [node.id, node.name]);
    const { dialog, form } = makeDialog(root, group ? "Изменить группу HA" : "Создать группу HA", context.signal);
    field(form, "name", "Название", { value: group?.name, required: true });
    field(form, "shared_domain", "Общий домен OpenVPN", { value: group?.shared_domain, required: true });
    field(form, "shared_domain_wireguard", "Общий домен WireGuard", { value: group?.shared_domain_wireguard });
    field(form, "primary_node_id", "Основной узел", {
      choices: [["", "Выберите узел"], ...choices], value: group?.primary_node_id, required: true
    });
    field(form, "replica_node_ids", "Реплики", {
      choices, value: group?.replica_node_ids, multiple: true, required: true
    });
    field(form, "sync_mode", "Режим синхронизации", {
      choices: [["manual_full", "Вручную"], ["auto", "Автоматически"]], value: group?.sync_mode || "manual_full"
    });
    const notice = feedback();
    form.append(notice);
    const { controls, save } = dialogActions(dialog, form, "Сохранить");
    function serialize() {
      const data = new FormData(form);
      data.set("replica_node_ids", data.getAll("replica_node_ids").join(","));
      return data;
    }
    controls.insertBefore(button("Предварительная проверка", (control) => {
      if (!form.reportValidity()) return;
      perform(context, control, notice, async () => {
        const data = await request(context, haPath + (group ? "/" + group.id : "") + "/preflight", "POST", serialize());
        if (Array.isArray(data?.warnings) && data.warnings.length) return data.warnings.join(" ");
        return data?.ready ? "Требования выполнены." : "Требования группы ещё не подтверждены.";
      });
    }), save);
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      perform(context, save, notice, async () => {
        await request(context, group ? haPath + "/" + group.id : haPath, group ? "PUT" : "POST", serialize());
        await reload();
        dialog.close();
      });
    });
    dialog.showModal();
  }

  function groupCard(group) {
    const card = create("article", "panel upload-panel");
    const header = create("div", "section-heading");
    header.append(create("h2", "", group.name), create("span", "pill", group.ready ? "Готова" : "Ожидает проверки"));
    const names = new Map(getNodes().map((node) => [node.id, node.name]));
    const name = (id) => names.get(id) || "Узел " + id;
    const primary = "Основной — " + name(group.primary_node_id);
    const replicas = "Реплики — " + (group.replica_node_ids || []).map(name).join(", ");
    card.append(header, create("p", "muted", group.shared_domain), create("p", "muted", primary),
      create("p", "muted", replicas), create("p", "muted", group.sync_mode === "auto" ? "Автоматически" : "Вручную"));
    const notice = feedback();
    const actions = create("div", "row-actions");
    const path = haPath + "/" + group.id;
    actions.append(button("Статус", (control) => perform(context, control, notice, async () => {
      const status = await request(context, path + "/status");
      return status?.summary || status?.message ||
        (Array.isArray(status?.warnings) && status.warnings.join(" ")) ||
        (status?.ready ? "Группа готова." : "Группа ожидает проверки.");
    })), button("Проверить", (control) => perform(context, control, notice, async () => {
      const status = await request(context, path + "/verify", "POST");
      return status?.summary || "Проверка завершена.";
    })), button("Изменить", () => editGroup(group)), button("Удалить", () =>
      confirmRemoval(root, context, "Удалить группу HA", group.name, async () => {
        await request(context, path, "DELETE");
        await reload();
      })));
    card.append(actions, notice);
    return card;
  }

  async function reload() {
    const payload = await request(context, haPath);
    const groups = Array.isArray(payload) ? payload : payload?.groups;
    if (!Array.isArray(groups)) throw new Error("Не удалось прочитать список групп HA.");
    cards.replaceChildren(...groups.map(groupCard));
    if (!groups.length) cards.append(create("p", "muted", "Группы синхронизации пока не созданы."));
  }

  report(target, "Загрузка групп…");
  reload().then(() => report(target)).catch((error) => {
    if (!context.signal.aborted) report(target, error.message, "error");
  });
}

window.apazModules ??= {};
window.apazModules.nodes = { mount: mountNodes };
window.apazModules.proxy = { mount: mountProxy };
