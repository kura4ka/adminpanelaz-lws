(() => {
  "use strict";

  const modules = window.apazModules ??= {};
  const featurePath = "/api/settings/features";
  const diagnosticsPath = "/api/settings/diagnostics";
  const filePath = "/api/settings/edit-files";
  const availableControls = new Set([
    "logs_dashboard", "server_monitor", "routing", "edit_files", "telegram", "proxy_nodes",
    "backups", "diagnostics_tests", "clients_page", "nodes", "action_logs", "traffic_sync",
    "panel_resource_metrics", "connection_history", "user_management"
  ]);

  const settingsGroups = [
    ["Личное", [
      ["Мой профиль", "/settings/personal", "Пароль и дополнительная защита при входе"]
    ]],
    ["Доступ", [
      ["Пользователи панели", "/settings/users", "Учётные записи, роли и доступ", "user_management"]
    ]],
    ["Сервер", [
      ["Резервные копии", "/settings/backup", "Архивы и загрузка резервных копий", "backups"]
    ]],
    ["Панель", [
      ["Разделы панели", "/settings/modules", "Управление доступностью функций"],
      ["Проверка работы", "/settings/tests", "Доступность панели, HTTPS и файлов", "diagnostics_tests"],
      ["Telegram", "/telegram", "Настройки и привязка Telegram", "telegram"]
    ]]
  ];

  const fileGroups = [
    ["hosts", "Сайты"],
    ["ips", "IP-адреса"],
    ["adblock", "Блокировка рекламы"],
    ["warp", "WARP"],
    ["dns", "DNS (Knot Resolver)"]
  ];

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text) node.textContent = text;
    return node;
  }

  function statusLine() {
    const line = element("p", "feedback");
    line.setAttribute("role", "status");
    line.hidden = true;
    return line;
  }

  function status(line, text = "", kind = "") {
    line.textContent = text;
    line.dataset.kind = kind;
    line.hidden = !text;
  }

  function go(path, text, context, className) {
    const link = element("a", className, text);
    link.href = new URL(path.slice(1), document.baseURI);
    link.addEventListener("click", event => {
      if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      context.navigate(path);
    });
    return link;
  }

  async function request(context, path, options) {
    const response = await context.api(path, options);
    if (!response.ok) {
      const error = new Error("Settings request failed");
      error.status = response.status;
      throw error;
    }
    return response;
  }

  function message(error, fallback) {
    if (error.status === 401) return "Сессия завершилась. Войдите снова.";
    if (error.status === 403) return "Раздел выключен или доступ ограничен.";
    return fallback;
  }

  async function mountLanding(root, context) {
    const feedback = statusLine();
    root.append(feedback);
    let features = {};
    const isAdmin = context.identity?.role === "admin";
    if (isAdmin) {
      status(feedback, "Загрузка настроек…");
      try {
        features = (await (await request(context, featurePath)).json()).features;
        status(feedback);
      } catch (error) {
        if (context.signal.aborted) return;
        status(feedback, message(error, "Не удалось загрузить состояние разделов."), "error");
      }
    }
    if (context.signal.aborted) return;
    for (const [title, entries] of settingsGroups) {
      if (title !== "Личное" && !isAdmin) continue;
      const group = element("section", "settings-group");
      const grid = element("div", "settings-grid");
      for (const [label, path, description, flag] of entries) {
        if (flag && features?.[flag] !== true) continue;
        const card = go(path, null, context, "panel settings-card");
        card.append(element("strong", null, label), element("span", "muted", description));
        grid.append(card);
      }
      if (!grid.children.length) continue;
      group.append(element("h2", null, title), grid);
      root.append(group);
    }
  }

  async function mountFeatures(root, context) {
    const feedback = statusLine();
    root.append(go("/settings", "Все настройки", context, "settings-back"), feedback);
    const list = element("div", "settings-toggle-list");
    root.append(list);

    function render(data, focusKey) {
      const groups = [["app_module", "Разделы приложения"], ["background", "Фоновые задачи"]];
      let target = null;
      list.replaceChildren();
      for (const [key, title] of groups) {
        const section = element("section", "settings-group");
        const controls = element("div", "panel settings-controls");
        for (const item of data.items) {
          if (item.group !== key || !availableControls.has(item.key)) continue;
          const label = element("label", "settings-toggle");
          const name = element("span", null, item.label);
          const checkbox = element("input");
          checkbox.type = "checkbox";
          checkbox.checked = item.enabled;
          checkbox.disabled = item.locked;
          if (item.locked) {
            name.append(element("small", "muted", "Требуется хотя бы один VPN-протокол"));
          }
          checkbox.addEventListener("change", async () => {
            const enabled = checkbox.checked;
            const switches = controls.closest(".settings-toggle-list").querySelectorAll("input");
            for (const control of switches) control.disabled = true;
            status(feedback, "Сохранение…");
            try {
              await request(context, featurePath, {
                method: "POST",
                body: new URLSearchParams({ key: item.key, enabled: enabled ? "1" : "0" })
              });
              const next = await (await request(context, featurePath)).json();
              if (context.signal.aborted) return;
              context.updateFeatures?.(next.features);
              render(next, item.key);
              status(feedback, "Настройка сохранена.", "success");
            } catch (error) {
              if (context.signal.aborted) return;
              render(data, item.key);
              status(feedback, error.status === 409 ? "Должен оставаться доступным раздел «Клиенты» или «Абоненты»."
                : message(error, "Не удалось сохранить настройку."), "error");
            }
          });
          if (item.key === focusKey) target = checkbox;
          label.append(name, checkbox);
          controls.append(label);
        }
        section.append(element("h2", null, title), controls);
        list.append(section);
      }
      target?.focus();
    }

    status(feedback, "Загрузка разделов…");
    try {
      const data = await (await request(context, featurePath)).json();
      if (context.signal.aborted) return;
      render(data);
      status(feedback);
    } catch (error) {
      if (!context.signal.aborted)
        status(feedback, message(error, "Не удалось загрузить разделы панели."), "error");
    }
  }

  async function mountFiles(root, context) {
    const feedback = statusLine();
    const layout = element("div", "settings-files");
    const sidebar = element("div", "panel settings-file-list");
    const reader = element("div", "panel settings-file-reader");
    const toolbar = element("div", "section-heading");
    const filename = element("label");
    filename.htmlFor = "apaz-config-content";
    const reload = element("button", "secondary", "Обновить");
    reload.type = "button";
    reload.disabled = true;
    const content = element("textarea", "settings-file-content");
    content.id = filename.htmlFor;
    content.readOnly = true;
    content.spellcheck = false;
    content.wrap = "off";
    content.hidden = true;
    toolbar.append(filename, reload);
    reader.append(toolbar, feedback, content);
    layout.append(sidebar, reader);
    root.append(layout);

    const choices = new Map();
    let selected = null;
    let currentRead = null;
    async function select(file) {
      selected = file;
      currentRead?.abort();
      if (!file) return;
      for (const [key, choice] of choices)
        choice.setAttribute("aria-pressed", String(key === file.key));
      filename.textContent = file.filename;
      content.hidden = true;
      content.value = "";
      reload.disabled = true;
      const controller = new AbortController();
      currentRead = controller;
      status(feedback, "Чтение файла…");
      try {
        const data = await (await request(context, filePath + "/" + encodeURIComponent(file.key), {
          signal: controller.signal
        })).json();
        if (context.signal.aborted || controller.signal.aborted) return;
        content.value = data.content;
        content.hidden = false;
        status(feedback, data.content ? "Только чтение" : "Файл пуст.");
      } catch (error) {
        if (context.signal.aborted || controller.signal.aborted) return;
        const problem = {
          409: "Файл изменился во время чтения. Обновите содержимое.",
          413: "Файл слишком велик для просмотра.",
          503: "Каталог локального узла или файл недоступен."
        }[error.status];
        status(feedback, problem || message(error, "Не удалось прочитать файл."), "error");
      } finally {
        if (currentRead === controller) reload.disabled = false;
      }
    }
    reload.addEventListener("click", () => select(selected));

    status(feedback, "Загрузка списка файлов…");
    try {
      const files = await (await request(context, filePath)).json();
      if (context.signal.aborted) return;
      for (const [key, title] of fileGroups) {
        const group = element("section", "settings-file-group");
        group.append(element("h2", null, title));
        for (const file of files.filter(entry => entry.group === key)) {
          const button = element("button", "secondary", file.title);
          button.type = "button";
          button.setAttribute("aria-pressed", "false");
          button.addEventListener("click", () => select(file));
          choices.set(file.key, button);
          group.append(button);
        }
        if (group.children.length > 1) sidebar.append(group);
      }
      if (files.length) await select(files[0]);
      else status(feedback, "Нет доступных файлов.");
    } catch (error) {
      if (!context.signal.aborted)
        status(feedback, message(error, "Не удалось открыть список файлов."), "error");
    }
  }

  async function mountDiagnostics(root, context) {
    const toolbar = element("div", "section-heading");
    const refresh = element("button", "primary", "Проверить");
    refresh.type = "button";
    toolbar.append(go("/settings", "Все настройки", context, "settings-back"), refresh);
    const feedback = statusLine();
    const report = element("ul", "panel settings-checks");
    report.hidden = true;
    root.append(toolbar, feedback, report);

    async function run() {
      refresh.disabled = true;
      status(feedback, "Проверка состояния…");
      try {
        const result = await (await request(context, diagnosticsPath)).json();
        if (context.signal.aborted) return;
        report.replaceChildren();
        for (const check of result.results) {
          const row = element("li");
          const title = element("strong", null, check.title);
          const badge = element("span", "pill", check.status === "ok" ? "Работает" : "Требует внимания");
          badge.dataset.state = check.status === "ok" ? "live" : "error";
          row.append(title, badge, element("p", "muted", check.detail));
          report.append(row);
        }
        report.hidden = false;
        status(feedback);
      } catch (error) {
        if (!context.signal.aborted)
          status(feedback, message(error, "Не удалось выполнить проверку."), "error");
      } finally {
        refresh.disabled = false;
      }
    }
    refresh.addEventListener("click", run);
    await run();
  }

  modules.settings = { mount: (root, context) =>
    context.tab === "modules" ? mountFeatures(root, context) : mountLanding(root, context) };
  modules.files = { mount: mountFiles };
  modules.diagnostics = { mount: mountDiagnostics };
})();
