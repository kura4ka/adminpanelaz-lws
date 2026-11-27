const tabs = new Map([
  ["overview", "Обзор"], ["analysis", "Анализ"], ["pipeline", "Обновление"],
  ["providers", "Провайдеры"], ["settings", "Настройки"]
]);
const formatNumber = new Intl.NumberFormat("ru-RU");
const importLimit = 8 * 1024 * 1024;

const messages = {
  no_source_routes: "Загрузите список CIDR для выбранного провайдера.",
  no_previous_revision: "Предыдущая сборка отсутствует.",
  no_published_routes: "Собранный список отсутствует.",
  no_routes_within_budget: "После сокращения не осталось маршрутов для сборки.",
  operation_in_progress: "Другая операция с CIDR уже выполняется.",
  routing_busy: "Другая операция с CIDR уже выполняется.",
  import_limit: "Размер файла превышает 8 МиБ.",
  source_limit: "Достигнут предел числа провайдеров.",
  build_limit: "Слишком много записей для одной сборки. Выберите провайдера.",
  invalid_request: "Проверьте имя провайдера и лимит маршрутов.",
  invalid_stored_source: "В базе CIDR обнаружено недопустимое имя провайдера.",
  invalid_stored_network: "В базе CIDR обнаружена некорректная сеть."
};

function create(tag, className, label) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (label !== undefined) element.textContent = label;
  return element;
}

function button(label, className = "secondary") {
  const element = create("button", className, label);
  element.type = "button";
  return element;
}

function report(element, message, kind = "") {
  element.hidden = !message;
  element.textContent = message;
  element.dataset.kind = kind;
}

function feedback() {
  const element = create("p", "feedback");
  element.setAttribute("role", "status");
  element.hidden = true;
  return element;
}

function errorMessage(status, result) {
  if (status === 401 || status === 403) return "Для этой операции войдите как администратор.";
  if (result?.state === "empty") return "В файле нет маршрутов IPv4.";
  if (result?.state === "invalid") {
    return result.error_line ? `Некорректная строка ${formatNumber.format(result.error_line)}.` : "Некорректный список CIDR.";
  }
  return messages[result?.error] || "Не удалось выполнить операцию с CIDR.";
}

function endpoint(action, query = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value) params.set(key, value);
  const suffix = params.toString();
  return "/api/cidr/" + action + (suffix ? "?" + suffix : "");
}

async function request(context, action, query, options) {
  const response = await context.api(endpoint(action, query), options);
  let payload;
  try { payload = await response.json(); }
  catch { throw new Error(errorMessage(response.status)); }
  if (!response.ok && payload.state !== "over_budget") throw new Error(errorMessage(response.status, payload));
  return payload;
}

async function withFeedback(context, control, target, action) {
  if (context.signal.aborted) return;
  control.disabled = true;
  report(target, "Выполняется…");
  try { await action(); }
  catch (error) {
    if (!context.signal.aborted) report(target, error instanceof TypeError ? "Нет связи с панелью." : error.message, "error");
  } finally { control.disabled = false; }
}

function card(label, value, detail) {
  const node = create("div", "panel resource");
  node.append(create("p", "resource-label", label), create("strong", "resource-value", value));
  if (detail) node.append(create("p", "resource-detail", detail));
  return node;
}

function overview(root, data) {
  const resources = create("div", "resources");
  resources.append(
    card("Маршрутов в сборке", formatNumber.format(data.routes)),
    card("Провайдеров", formatNumber.format(data.sources.length)),
    card("Бюджет OpenVPN", formatNumber.format(data.budget), "Лимит для новой сборки")
  );
  const state = create("div", "panel inspection");
  state.append(create("h2", "", "Списки контроллера"));
  state.append(create("p", "muted", data.revision ? `Сборка №${data.revision}` : "Списки ещё не собраны."));
  if (data.previous_revision) state.append(create("p", "muted", `Доступен откат к сборке №${data.previous_revision}.`));
  root.append(resources, state);
}

function sourceList(root, data, context, preview = false) {
  const wrapper = create("div", "panel table-scroll");
  if (!data.sources.length) {
    wrapper.append(create("p", "empty", "Добавьте список на вкладке «Обновление»."));
    root.append(wrapper);
    return;
  }
  wrapper.tabIndex = 0;
  wrapper.setAttribute("role", "region");
  wrapper.setAttribute("aria-label", "Списки провайдеров");
  const table = create("table", "collection-table");
  const head = table.createTHead().insertRow();
  for (const label of ["Провайдер", "Записей CIDR", "Маршрутов в сборке"]) {
    const column = create("th", label === "Провайдер" ? "" : "numeric", label);
    column.scope = "col";
    head.append(column);
  }
  if (!preview) {
    const column = create("th", "", "Действия");
    column.scope = "col";
    head.append(column);
  }
  const notices = feedback();
  const body = table.createTBody();
  for (const source of data.sources) {
    const row = body.insertRow();
    row.append(create("td", "", source.name), create("td", "numeric", formatNumber.format(source.input_routes)),
      create("td", "numeric", formatNumber.format(source.routes)));
    if (preview) continue;
    const actions = row.insertCell();
    if (source.routes) {
      const download = button("Скачать список");
      download.addEventListener("click", () => withFeedback(context, download, notices, async () => {
        const response = await context.api(endpoint("export", { source: source.name, format: "artifact" }));
        if (!response.ok) throw new Error(errorMessage(response.status, await response.json().catch(() => undefined)));
        const link = create("a");
        link.href = URL.createObjectURL(await response.blob());
        link.download = source.name.endsWith(".txt") ? source.name : source.name + "-ips.txt";
        link.click();
        const url = link.href;
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        report(notices, "Список готов к скачиванию.", "success");
      }));
      actions.append(download);
    }
  }
  wrapper.append(table);
  root.append(notices, wrapper);
}

function buildForm(root, data, context, canPublish) {
  const form = create("form", "panel upload-panel");
  const controls = create("div", "upload-control");
  const select = create("select");
  select.setAttribute("aria-label", "Провайдеры");
  select.add(new Option("Все провайдеры", ""));
  for (const source of data.sources) {
    if (source.input_routes) select.add(new Option(source.name, source.name));
  }
  const budget = create("input");
  budget.type = "number";
  budget.min = "1";
  budget.max = "10000";
  budget.placeholder = String(data.budget);
  budget.setAttribute("aria-label", "Лимит маршрутов");
  const label = create("label", "muted", "Лимит маршрутов ");
  label.append(budget);
  const trim = create("input");
  trim.type = "checkbox";
  const trimLabel = create("label", "muted");
  trimLabel.append(trim, " Сократить списки до лимита");
  const preview = button("Оценить");
  preview.type = "submit";
  const publish = button("Сгенерировать из БД", "primary");
  const notices = feedback();
  const result = create("div");
  const compile = async (action, trigger) => {
    if (!form.reportValidity()) return;
    await withFeedback(context, trigger, notices, async () => {
      result.replaceChildren();
      const response = await request(context, action, {
        source: select.value, budget: budget.value, format: trim.checked ? "trim" : ""
      }, { method: "POST" });
      if (context.signal.aborted) return;
      const counts = `${formatNumber.format(response.total_routes)} из ${formatNumber.format(response.budget)} маршрутов`;
      const trimmed = response.trimmed ? ` До сокращения ${formatNumber.format(response.original_routes)}.` : "";
      if (response.over_budget) report(notices, `Превышен бюджет OpenVPN. ${counts}.`, "error");
      else if (action === "publish") {
        report(notices, `Сборка №${response.revision} сохранена на контроллере. ${counts}.${trimmed}`, "success");
      } else report(notices, `${counts}.${trimmed}`, "success");
      sourceList(result, response, context, true);
      if (action === "publish" && !response.over_budget) {
        const current = await request(context, "status");
        if (!context.signal.aborted) root.dispatchEvent(new CustomEvent("cidr-state", { detail: current }));
      }
    });
  };
  form.addEventListener("submit", (event) => { event.preventDefault(); compile("preview", preview); });
  publish.addEventListener("click", () => compile("publish", publish));
  controls.append(select, label, preview);
  if (canPublish) controls.append(publish);
  form.append(create("h2", "", canPublish ? "Сборка списков" : "Оценка бюджета маршрутов"),
    create("p", "muted", "Соседние и вложенные сети объединяются внутри списка каждого провайдера."), controls,
    trimLabel, notices);
  root.append(form, result);
}

function pipeline(root, data, context) {
  const form = create("form", "panel upload-panel");
  const source = create("input");
  source.name = "source";
  source.placeholder = "custom-ips.txt";
  source.required = true;
  source.maxLength = 64;
  source.pattern = "[A-Za-z0-9][A-Za-z0-9_.\\-]{0,63}";
  source.setAttribute("aria-label", "Имя провайдера");
  source.value = "custom-ips.txt";
  const file = create("input");
  file.type = "file";
  file.accept = ".txt,.cidr,text/plain";
  file.required = true;
  file.setAttribute("aria-label", "Список IPv4/CIDR");
  const submit = button("Импортировать", "primary");
  submit.type = "submit";
  const controls = create("div", "upload-control");
  const importFeedback = feedback();
  controls.append(source, file, submit);
  form.append(create("h2", "", "Свои CIDR"), create("p", "muted", "Текстовый файл до 8 МиБ. Один IPv4-адрес или сеть на строку."),
    controls, importFeedback);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const selected = file.files[0];
    if (!selected) return;
    if (selected.size > importLimit) {
      report(importFeedback, messages.import_limit, "error");
      return;
    }
    withFeedback(context, submit, importFeedback, async () => {
      const response = await request(context, "import", { source: source.value }, {
        method: "POST", body: selected, headers: { "Content-Type": "application/octet-stream" }
      });
      if (context.signal.aborted) return;
      const note = response.policy_skipped ? ` Пропущено ${formatNumber.format(response.policy_skipped)}.` : "";
      report(importFeedback, `Сохранено ${formatNumber.format(response.published)} записей.${note}`, "success");
      file.value = "";
      const current = await request(context, "status");
      if (!context.signal.aborted) {
        build.replaceChildren();
        buildForm(build, current, context, true);
      }
    });
  });

  const build = create("div");
  buildForm(build, data, context, true);
  const restore = create("div", "panel upload-panel");
  const restoreButton = button("Откатить сборку");
  restoreButton.disabled = !data.previous_revision;
  const restoreFeedback = feedback();
  const previous = create("p", "muted", data.previous_revision ? `Доступна сборка №${data.previous_revision}.` : "Предыдущая сборка отсутствует.");
  build.addEventListener("cidr-state", ({ detail }) => {
    restoreButton.disabled = !detail.previous_revision;
    previous.textContent = detail.previous_revision ? `Доступна сборка №${detail.previous_revision}.` : "Предыдущая сборка отсутствует.";
  });
  restoreButton.addEventListener("click", async () => {
    if (!window.confirm("Вернуть предыдущую сборку списков контроллера?")) return;
    let reverted = false;
    await withFeedback(context, restoreButton, restoreFeedback, async () => {
      const response = await request(context, "rollback", {}, { method: "POST" });
      if (context.signal.aborted) return;
      previous.textContent = "Предыдущая сборка отсутствует.";
      report(restoreFeedback, `Восстановлена сборка №${response.revision}.`, "success");
      reverted = true;
    });
    if (reverted) restoreButton.disabled = true;
  });
  restore.append(create("h2", "", "Откат"), previous, restoreButton, restoreFeedback);
  root.append(form, build, restore);
}

function settings(root, data) {
  const block = create("div", "panel upload-panel");
  block.append(create("h2", "", "Бюджет маршрутов OpenVPN"),
    create("p", "muted", `${formatNumber.format(data.budget)} маршрутов по умолчанию. Лимит отдельной сборки задаётся во вкладке «Обновление».`));
  root.append(block);
}

async function mount(root, context) {
  const requested = new URLSearchParams(location.search).get("tab");
  const current = tabs.has(requested) ? requested : "overview";
  const nav = create("nav", "panel subnav");
  nav.setAttribute("aria-label", "Вкладки маршрутизации");
  for (const [tab, label] of tabs) {
    const control = button(label, "");
    control.setAttribute("aria-pressed", String(tab === current));
    control.addEventListener("click", () => context.navigate("/routing?tab=" + tab));
    nav.append(control);
  }
  const content = create("div");
  const state = create("p", "feedback", "Загрузка списков…");
  state.setAttribute("role", "status");
  content.append(state);
  root.replaceChildren(nav, content);
  try {
    const data = await request(context, "status");
    if (context.signal.aborted) return;
    content.replaceChildren();
    if (current === "overview") overview(content, data);
    if (current === "analysis") buildForm(content, data, context, false);
    if (current === "pipeline") pipeline(content, data, context);
    if (current === "providers") sourceList(content, data, context);
    if (current === "settings") settings(content, data);
  } catch (error) {
    if (!context.signal.aborted) report(state, error instanceof TypeError ? "Нет связи с панелью." : error.message, "error");
  }
}

window.apazModules ??= {};
window.apazModules.cidr = { mount };
