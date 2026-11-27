(() => {
  "use strict";

  const apiPath = "/api/settings/users";
  const errors = {
    invalid_user: "Проверьте имя, роль и пароль. Длина пароля от 12 символов.",
    invalid_search: "Сократите поисковый запрос.",
    username_taken: "Это имя пользователя уже занято.",
    user_not_found: "Пользователь уже удалён.",
    stale_user: "Данные пользователя изменились. Обновите список и повторите действие.",
    last_admin: "В панели должен остаться администратор с доступом ко входу.",
    use_personal_settings: "Для изменения своего пароля откройте «Мой профиль».",
    user_cleanup_pending: "Доступ удалён. Повторите действие, чтобы завершить очистку данных.",
    unauthorized: "Сессия завершилась. Войдите снова.",
    forbidden: "Действие доступно администратору."
  };

  function node(tag, className = "", text = "") {
    const item = document.createElement(tag);
    item.className = className;
    item.textContent = text;
    return item;
  }

  function button(text, action, primary = false) {
    const control = node("button", primary ? "primary" : "secondary", text);
    control.type = "button";
    control.addEventListener("click", action);
    return control;
  }

  function status(line, text = "", kind = "") {
    line.textContent = text;
    line.dataset.kind = kind;
    line.hidden = !text;
  }

  async function request(context, path, method = "GET", fields) {
    const response = await context.api(path, { method, body: fields ? new URLSearchParams(fields) : undefined });
    const body = await response.json();
    if (!response.ok) throw new Error(errors[body.error] || "Операция с учётной записью не выполнена.");
    return body;
  }

  function addField(form, caption, control, name) {
    const label = node("label", "", caption);
    control.name = name;
    label.append(control);
    form.append(label);
    return control;
  }

  function addName(form) {
    const input = node("input");
    input.autocomplete = "off";
    input.required = true;
    input.maxLength = 128;
    return addField(form, "Логин", input, "username");
  }

  function addPassword(form, caption) {
    const input = node("input");
    input.type = "password";
    input.required = true;
    input.minLength = 12;
    input.maxLength = 1024;
    input.autocomplete = "new-password";
    return addField(form, caption, input, "password");
  }

  function addFlag(form, name, caption, checked) {
    const input = node("input");
    input.type = "checkbox";
    input.checked = checked;
    addField(form, caption, input, name);
    return input;
  }

  function addOptions(form, user = {}) {
    const role = node("select");
    for (const [value, text] of [["user", "Пользователь"], ["admin", "Администратор"]]) {
      const option = node("option", "", text);
      option.value = value;
      role.append(option);
    }
    role.value = user.role || "user";
    addField(form, "Роль", role, "role");
    return {
      role,
      is_active: addFlag(form, "is_active", "Учётная запись активна", user.is_active ?? true),
      panel_login_enabled: addFlag(form, "panel_login_enabled", "Разрешить вход в панель", user.panel_login_enabled ?? true),
      must_change_password: addFlag(form, "must_change_password", "Потребовать смену пароля", user.must_change_password ?? true)
    };
  }

  function userSettings(controls) {
    return Object.fromEntries(Object.entries(controls).map(([key, control]) => [key,
      control.type === "checkbox" ? Number(control.checked) : control.value]));
  }

  function dialogFor(root, title, submitTitle, fill, save, context) {
    const dialog = node("dialog", "authentication panel nodes-dialog");
    const form = node("form");
    const titleElement = node("h2", "", title);
    dialog.setAttribute("aria-label", title);
    const message = node("p", "feedback");
    message.setAttribute("role", "status");
    const state = fill(form);
    const controls = node("div", "form-actions");
    const submit = node("button", "primary", submitTitle);
    submit.type = "submit";
    const cancel = button("Отмена", () => dialog.close());
    controls.append(submit, cancel);
    form.append(controls, message);
    dialog.append(titleElement, form);
    root.append(dialog);
    const remove = () => { form.reset(); dialog.remove(); };
    context.signal.addEventListener("abort", remove, { once: true });
    dialog.addEventListener("close", () => {
      context.signal.removeEventListener("abort", remove);
      remove();
    }, { once: true });
    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (submit.disabled) return;
      submit.disabled = true;
      cancel.disabled = true;
      status(message, "Сохраняем…");
      try {
        await save(state);
        if (!context.signal.aborted) dialog.close();
      } catch (error) {
        if (!context.signal.aborted) status(message, error.message, "error");
      } finally {
        submit.disabled = false;
        cancel.disabled = false;
      }
    });
    dialog.addEventListener("cancel", event => { if (submit.disabled) event.preventDefault(); });
    dialog.showModal();
  }

  async function mount(root, context) {
    const toolbar = node("div", "upload-control");
    const output = node("p", "feedback");
    output.setAttribute("role", "status");
    const tableWrap = node("div", "panel table-scroll");
    const table = node("table", "collection-table");
    const head = node("thead");
    const headings = node("tr");
    for (const text of ["Пользователь", "Статус", "Роль", "Вход в панель", "Telegram", "Действия"]) {
      const cell = node("th", "", text);
      cell.scope = "col";
      headings.append(cell);
    }
    head.append(headings);
    const list = node("tbody");
    table.append(head, list);
    tableWrap.append(table);
    const pages = node("div", "upload-control");
    const cursors = [null];
    let page = 0;
    let pending = false;
    let query = "";
    const searchForm = node("form", "upload-control");
    const term = node("input");
    term.type = "search";
    term.maxLength = 128;
    term.placeholder = "Поиск по логину или роли";
    term.setAttribute("aria-label", "Поиск пользователей");
    const search = node("button", "secondary", "Найти");
    search.type = "submit";
    searchForm.append(term, search);
    searchForm.addEventListener("submit", event => {
      event.preventDefault();
      if (pending) return;
      query = term.value.trim();
      cursors.length = 1;
      page = 0;
      load(0);
    });
    const previous = button("Назад", () => load(page - 1));
    const next = button("Далее", () => load(page + 1));
    pages.append(previous, next);
    pages.hidden = true;

    function editUser(user) {
      dialogFor(root, `Редактировать ${user.username}`, "Сохранить", form => addOptions(form, user), async controls => {
        await request(context, `${apiPath}/${user.id}`, "PUT", { ...userSettings(controls), revision: user.revision });
        await load(page, "Изменения сохранены.");
      }, context);
    }

    function resetPassword(user) {
      dialogFor(root, `Пароль пользователя ${user.username}`, "Сменить пароль", form => ({
        password: addPassword(form, "Новый пароль"),
        must_change_password: addFlag(form, "must_change_password", "Потребовать смену пароля при входе", true)
      }), async controls => {
        await request(context, `${apiPath}/${user.id}/reset-password`, "POST", { ...userSettings(controls), revision: user.revision });
        await load(page, "Пароль изменён. Прежние сессии завершены.");
      }, context);
    }

    function deleteUser(user) {
      dialogFor(root, `Удалить ${user.username}`, "Удалить", form => {
        form.append(node("p", "", "Пользователь потеряет доступ к панели. Его активные сессии будут завершены."));
      }, async () => {
        await request(context, `${apiPath}/${user.id}?revision=${encodeURIComponent(user.revision)}`, "DELETE");
        await load(page, "Пользователь удалён.");
      }, context);
    }

    function makeRow(user) {
      const row = node("tr");
      const ownAccount = user.username === context.identity?.username;
      const role = user.role === "admin" ? "Администратор" : "Пользователь";
      const availability = user.is_active ? "Активен" : "Отключён";
      const factorPending = user.legacy_totp ? !user.totp_available : user.legacy_passkeys;
      const signIn = !user.panel_login_enabled ? "Запрещён" : factorPending ? "Нужен перенос второго фактора" :
        user.native_totp_required && !user.totp_available ? "Второй фактор недоступен" :
        user.must_change_password ? "Требуется смена пароля" : "Разрешён";
      row.append(node("td", "", user.username), node("td", "", availability), node("td", "", role),
        node("td", "", signIn), node("td", "", user.telegram_linked ? "Привязан" : "—"));
      const actionCell = node("td");
      const actions = node("div", "row-actions");
      actions.append(button("Редактировать", () => editUser(user)));
      if (!ownAccount) actions.append(button("Сменить пароль", () => resetPassword(user)), button("Удалить", () => deleteUser(user)));
      actionCell.append(actions);
      row.append(actionCell);
      return row;
    }

    async function load(target, successMessage = "") {
      if (pending || target < 0 || target >= cursors.length || context.signal.aborted) return;
      pending = true;
      previous.disabled = next.disabled = true;
      search.disabled = true;
      status(output, "Загружаем пользователей…");
      let returnToPrevious = false;
      try {
        const cursor = cursors[target];
        const params = new URLSearchParams();
        if (cursor !== null) params.set("after", cursor);
        if (query) params.set("q", query);
        const { users, next_after: nextAfter } = await request(context, params.size ? `${apiPath}?${params}` : apiPath);
        if (context.signal.aborted) return;
        if (!users.length && target) {
          returnToPrevious = true;
        } else {
          page = target;
          cursors.length = page + 1;
          if (nextAfter !== null) cursors.push(nextAfter);
          list.replaceChildren(...users.map(makeRow));
          tableWrap.hidden = users.length === 0;
          pages.hidden = !page && nextAfter === null;
          const empty = query ? "Ничего не найдено." : "Нет учётных записей панели.";
          status(output, successMessage || (!users.length ? empty : ""), successMessage ? "success" : "");
        }
      } catch (error) {
        if (!context.signal.aborted) status(output, error.message, "error");
      } finally {
        pending = false;
        search.disabled = false;
        previous.disabled = page === 0;
        next.disabled = cursors.length <= page + 1;
      }
      if (returnToPrevious) await load(target - 1, successMessage);
    }

    toolbar.append(searchForm, button("Добавить пользователя", () => {
      dialogFor(root, "Новый пользователь", "Создать", form => ({
        username: addName(form),
        password: addPassword(form, "Пароль"),
        ...addOptions(form)
      }), async controls => {
        await request(context, apiPath, "POST", userSettings(controls));
        await load(page, "Пользователь создан.");
      }, context);
    }, true), button("Обновить", () => load(page)));
    root.append(toolbar, output, tableWrap, pages);
    tableWrap.hidden = true;
    await load(0);
  }

  (window.apazModules ??= {}).users = { mount };
})();
