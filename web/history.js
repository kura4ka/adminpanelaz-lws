"use strict";

const labels = {
  login: "Вход",
  login_success: "Вход",
  login_failed: "Вход",
  logout: "Выход",
  password_change: "Смена пароля",
  backup_create: "Создание резервной копии",
  backup_upload: "Загрузка резервной копии",
  backup_delete: "Удаление резервной копии",
  backup_restore: "Восстановление из резервной копии",
  client_change: "Изменение VPN-клиента",
  node_change: "Изменение узла",
  routing_change: "Изменение маршрутизации",
  settings_change: "Изменение настроек"
};

const missing = "—";
const dateFormat = new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "short" });
const numberFormat = new Intl.NumberFormat("ru-RU", { maximumFractionDigits: 1 });
const colors = ["#64d4df", "#9dbbff", "#bca6f6", "#ecd98e"];
const finite = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;

function item(tag, content, className) {
  const node = document.createElement(tag);
  if (content !== undefined) node.textContent = content;
  if (className) node.className = className;
  return node;
}

function formatDate(value) {
  const date = new Date(value * 1000);
  return finite(value) && Number.isFinite(date.getTime()) ? dateFormat.format(date) : missing;
}

function number(value) {
  return finite(value) ? numberFormat.format(value) : missing;
}

function bytes(value) {
  if (!finite(value)) return missing;
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ", "ЭиБ"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return number(value) + " " + units[index];
}

function ratio(used, total) {
  return finite(used) && finite(total) && total > 0 ? used * 100 / total : null;
}

function percent(value) {
  return finite(value) ? number(value) + " %" : missing;
}

const sections = {
  traffic: {
    title: "История трафика VPN",
    kind: "traffic",
    format: bytes,
    series: [
      ["Получено", row => row.rx_bytes],
      ["Отправлено", row => row.tx_bytes]
    ]
  },
  resources: {
    title: "История ресурсов",
    kind: "resources",
    format: percent,
    maximum: 100,
    series: [
      ["Процессор", row => row.cpu_percent],
      ["Оперативная память", row => ratio(row.memory_used_bytes, row.memory_total_bytes)],
      ["Диск", row => row.disk_percent ?? ratio(row.disk_used_bytes, row.disk_total_bytes)]
    ]
  },
  connections: {
    title: "История подключений",
    kind: "connections",
    format: number,
    series: [
      ["OpenVPN", row => row.openvpn],
      ["WireGuard", row => row.wireguard],
      ["AmneziaWG 2.0", row => row.amneziawg2],
      ["Всего", row => row.total]
    ]
  },
  logs: { title: "Журнал действий", kind: "audit" }
};

function table(title, headings, values) {
  const area = item("div", undefined, "panel table-scroll");
  area.tabIndex = 0;
  area.setAttribute("role", "region");
  area.setAttribute("aria-label", title);
  const grid = item("table");
  const head = item("thead");
  const header = item("tr");
  for (const heading of headings) {
    const column = item("th", heading);
    column.scope = "col";
    header.append(column);
  }
  head.append(header);
  const body = item("tbody");
  for (const valuesInRow of values) {
    const row = item("tr");
    row.append(...valuesInRow.map(value => item("td", value)));
    body.append(row);
  }
  grid.append(head, body);
  area.append(grid);
  return area;
}

function draw(canvas, report, section, days, client) {
  const display = canvas.getBoundingClientRect().width;
  if (display <= 0) return;
  const scale = window.devicePixelRatio || 1;
  const height = 180;
  canvas.width = Math.round(display * scale);
  canvas.height = Math.round(height * scale);
  const drawing = canvas.getContext("2d");
  if (!drawing) return;
  drawing.scale(scale, scale);
  drawing.font = "11px system-ui";
  drawing.lineWidth = 1;

  const { points, from: start, through: end } = report;
  if (!finite(start) || !finite(end) || start >= end) return;
  const largest = section.maximum ?? Math.max(1, ...points.flatMap(point =>
    section.series.map(series => series[1](point) ?? 0)));
  const x0 = Math.max(54, Math.ceil(drawing.measureText(section.format(largest)).width) + 8);
  const x1 = display - 12;
  const y0 = 18;
  const y1 = height - 26;
  if (x1 <= x0) return;

  const style = getComputedStyle(canvas);
  drawing.strokeStyle = style.getPropertyValue("--border").trim() || "#334155";
  drawing.fillStyle = style.getPropertyValue("--muted").trim() || "#7e8d9f";
  drawing.textAlign = "right";
  drawing.textBaseline = "middle";
  for (let index = 0; index <= 4; index++) {
    const y = y0 + (y1 - y0) * index / 4;
    drawing.beginPath();
    drawing.moveTo(x0, y);
    drawing.lineTo(x1, y);
    drawing.stroke();
    drawing.fillText(section.format(largest * (4 - index) / 4), x0 - 7, y);
  }
  drawing.textAlign = "left";
  drawing.fillText(formatDate(start), x0, height - 9);
  drawing.textAlign = "right";
  drawing.fillText(formatDate(end), x1, height - 9);

  const dayBucket = client ? 3600 : section.kind === "resources" ? 720 : 600;
  const maximumGap = (days === 1 ? dayBucket : days === 7 ? 7200 : 21600) * 2;
  for (const [index, [, readValue]] of section.series.entries()) {
    let previous = null;
    drawing.strokeStyle = colors[index];
    drawing.fillStyle = colors[index];
    drawing.lineWidth = 2;
    for (const point of points) {
      const value = readValue(point);
      if (!finite(value) || !finite(point.timestamp)) {
        previous = null;
        continue;
      }
      const x = x0 + Math.max(0, Math.min(1, (point.timestamp - start) / (end - start))) * (x1 - x0);
      const y = y1 - Math.min(1, value / largest) * (y1 - y0);
      if (previous && point.timestamp - previous.timestamp <= maximumGap) {
        drawing.beginPath();
        drawing.moveTo(previous.x, previous.y);
        drawing.lineTo(x, y);
        drawing.stroke();
      }
      drawing.beginPath();
      drawing.arc(x, y, 2, 0, Math.PI * 2);
      drawing.fill();
      previous = { x, y, timestamp: point.timestamp };
    }
  }
}

function showAudit(content, section, points) {
  content.replaceChildren(table(section.title, ["Время", "Действие", "ID пользователя", "Результат"],
    points.map(row => [formatDate(row.timestamp), labels[row.action] || row.action || missing,
      number(row.actor_id), row.success === null ? missing : row.success ? "Успешно" : "Отклонено"])));
}

function showChart(content, section, report, days, client, signal) {
  const { points } = report;
  const seriesNames = section.series.map(series => series[0]);
  const chart = item("div", undefined, "panel resource");
  const canvas = item("canvas");
  canvas.setAttribute("aria-hidden", "true");
  canvas.style.display = "block";
  canvas.style.width = "100%";
  canvas.style.height = "180px";
  const legend = item("div", undefined, "row-actions");
  for (const [index, name] of seriesNames.entries()) {
    const label = item("span", undefined, "muted");
    const marker = item("span", "● ");
    marker.style.color = colors[index];
    marker.setAttribute("aria-hidden", "true");
    label.append(marker, document.createTextNode(name));
    legend.append(label);
  }
  chart.append(canvas, legend);
  const details = item("details", undefined, "inspection");
  details.append(item("summary", "Таблица значений"));

  const status = section.kind === "traffic";
  const columns = ["Время", ...seriesNames, ...(status ? ["Данные"] : [])];
  const values = points.map(row => [
    formatDate(row.timestamp), ...section.series.map(series => section.format(series[1](row))),
    ...(status ? [row.complete ? "Полные" : "Неполные"] : [])
  ]);
  details.append(table(section.title, columns, values));

  content.replaceChildren(chart, details);
  const resize = new ResizeObserver(() => draw(canvas, report, section, days, client));
  resize.observe(canvas);
  signal.addEventListener("abort", () => resize.disconnect(), { once: true });
}

function mount(root, context) {
  const section = sections[context.tab];
  if (!section) return;
  const pageParams = new URLSearchParams(location.search);
  const client = section.kind === "traffic" ? pageParams.get("client") : null;
  const heading = item("div", undefined, "section-heading");
  const title = item("h2", client ? section.title + " · " + client : section.title);
  const actions = item("div", undefined, "row-actions");
  const periodLabels = [[1, "24 часа"], [7, "7 дней"], [30, "30 дней"]];
  const periods = periodLabels.map(([days, name]) => {
    const button = item("button", name, "secondary");
    button.type = "button";
    button.addEventListener("click", () => load(days), { signal: context.signal });
    return [days, button];
  });
  actions.append(...periods.map(([, button]) => button));
  const refresh = item("button", "Обновить", "secondary");
  refresh.type = "button";
  actions.append(refresh);
  if (client) {
    const clear = item("button", "Все клиенты", "secondary");
    clear.type = "button";
    clear.addEventListener("click", () => context.navigate("/monitoring?tab=traffic"), { signal: context.signal });
    actions.append(clear);
  }
  heading.append(title, actions);
  const state = item("p", undefined, "feedback");
  state.setAttribute("role", "status");
  const content = item("div");
  root.replaceChildren(heading, state, content);

  let selected = 1;
  let current;
  context.signal.addEventListener("abort", () => current?.abort(), { once: true });
  refresh.addEventListener("click", () => load(selected), { signal: context.signal });

  async function load(days) {
    selected = days;
    for (const [value, button] of periods) {
      button.setAttribute("aria-pressed", String(value === days));
      button.className = value === days ? "primary" : "secondary";
    }
    current?.abort();
    const request = new AbortController();
    current = request;
    state.textContent = "Загрузка…";
    delete state.dataset.kind;
    content.replaceChildren();
    try {
      const params = new URLSearchParams({ kind: section.kind, days });
      if (client) params.set("client", client);
      const response = await context.api("/api/monitor/history?" + params, {
        signal: request.signal
      });
      if (request.signal.aborted) return;
      if (response.status === 401 || response.status === 403) {
        state.textContent = "Войдите как администратор, чтобы открыть историю.";
        return;
      }
      if (!response.ok) throw new Error("history");
      const result = await response.json();
      if (request.signal.aborted) return;
      const points = Array.isArray(result.points) ? result.points : [];
      const available = section.series?.filter(([, read]) => points.some(point => finite(read(point))));
      if (!points.length || (available && !available.length)) {
        state.textContent = "За выбранный период нет данных.";
        return;
      }
      const incomplete = section.kind === "traffic" && points.some(point => !point.complete);
      state.textContent = incomplete ? "Часть снимков VPN недоступна. В итогах учтены полученные данные." : "";
      if (section.kind === "audit") showAudit(content, section, points);
      else showChart(content, { ...section, series: available }, result, days, client, request.signal);
    } catch {
      if (request.signal.aborted) return;
      state.dataset.kind = "error";
      state.textContent = "Не удалось загрузить историю.";
    }
  }

  load(selected);
}

window.apazModules ??= {};
window.apazModules.history = { mount };
