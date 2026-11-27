(() => {
  "use strict";

  const endpoint = "/api/auth/totp";
  const messages = {
    unauthorized: "Сессия завершилась. Войдите снова.",
    password_change_required: "Сначала смените пароль.",
    too_many_attempts: "Слишком много попыток. Повторите позже.",
    totp_unavailable: "Двухфакторная аутентификация недоступна.",
    totp_already_enabled: "Двухфакторная аутентификация уже включена.",
    totp_incomplete: "Хранилище двухфакторной аутентификации требует восстановления.",
    legacy_totp_required: "Двухфакторная аутентификация обязательна для этой перенесённой учётной записи.",
    invalid_second_factor: "Код неверный, просрочен или уже использован. Попробуйте следующий код."
  };

  function element(tag, text = "", className = "") {
    const node = document.createElement(tag);
    node.textContent = text;
    node.className = className;
    return node;
  }

  function button(label, kind = "secondary") {
    const node = element("button", label, kind);
    node.type = "button";
    return node;
  }

  async function mount(root, context) {
    if (context.identity?.must_change_password || context.identity?.method !== "session") return;
    const card = element("section", "", "panel upload-panel");
    const status = element("p", "Загрузка состояния…", "muted");
    const feedback = element("p", "", "feedback");
    feedback.setAttribute("role", "status");
    feedback.hidden = true;
    const controls = element("div");
    const output = element("div");
    card.append(element("h2", "Двухфакторная аутентификация"), status, feedback, controls, output);
    root.replaceChildren(card);

    function announce(text = "", kind = "") {
      feedback.textContent = text;
      feedback.dataset.kind = kind;
      feedback.hidden = !text;
    }

    async function request(path = "", body) {
      const response = await context.api(endpoint + path, path ? { method: "POST", body } : {});
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error);
      return payload;
    }

    function report(error) {
      if (!context.signal.aborted)
        announce(messages[error.message] || "Не удалось выполнить действие.", "error");
    }

    function showRecovery(codes) {
      if (!codes.length) return;
      const items = element("ul");
      for (const value of codes) {
        const item = element("li");
        item.append(element("code", value));
        items.append(item);
      }
      const clear = button("Скрыть коды");
      clear.addEventListener("click", () => output.replaceChildren());
      output.replaceChildren(element("h3", "Резервные коды"),
        element("p", "Сохраните эти коды. Каждый код можно использовать один раз.", "muted"), items, clear);
    }

    function showCodeForm(path, heading, action, label, contents = []) {
      output.replaceChildren();
      const form = element("form", "", "authentication");
      form.method = "post";
      const fieldLabel = element("label", label);
      fieldLabel.htmlFor = "totp-action-code";
      const input = element("input");
      input.id = fieldLabel.htmlFor;
      input.name = "code";
      input.autocomplete = "one-time-code";
      input.maxLength = 12;
      input.required = true;
      if (path === "/enable") input.inputMode = "numeric";
      input.spellcheck = false;
      const submit = button(action, "primary");
      submit.type = "submit";
      const cancel = button("Отмена");
      cancel.addEventListener("click", async () => {
        announce();
        try { await render(); } catch (error) { report(error); }
      });
      const actions = element("div", "", "row-actions");
      actions.append(submit, cancel);
      form.append(element("h3", heading), ...contents, fieldLabel, input, actions);
      controls.replaceChildren(form);
      input.focus();
      form.addEventListener("submit", async event => {
        event.preventDefault();
        submit.disabled = true;
        cancel.disabled = true;
        announce();
        try {
          const result = await request(path, new URLSearchParams({ code: input.value }));
          input.value = "";
          if (context.signal.aborted) return;
          if (!result.sessions_revoked)
            announce("Настройка сохранена. Не удалось завершить другие сеансы.", "error");
          else
            announce("Настройка сохранена.", "success");
          showRecovery(result.recovery_codes);
          await render();
        } catch (error) {
          report(error);
          input.select();
        } finally {
          submit.disabled = false;
          cancel.disabled = false;
        }
      });
    }

    async function startEnrollment(control) {
      control.disabled = true;
      announce();
      try {
        const { secret } = await request("/setup");
        if (context.signal.aborted) return;
        const issuer = "AdminPanelAZ";
        const label = encodeURIComponent(issuer + ":" + context.identity.username);
        const params = new URLSearchParams({ secret, issuer });
        const open = element("a", "Открыть приложение-аутентификатор");
        open.href = `otpauth://totp/${label}?${params}`;
        const manual = element("p");
        manual.append(element("code", secret));
        showCodeForm("/enable", "Подключение приложения", "Включить", "Код из приложения", [
          open, element("p", "При ручном вводе выберите код по времени и добавьте этот ключ.", "muted"), manual
        ]);
      } catch (error) { report(error); }
      finally { control.disabled = false; }
    }

    async function render() {
      const current = await request();
      if (context.signal.aborted) return;
      controls.replaceChildren();
      if (!current.configured) {
        status.textContent = "Двухфакторная аутентификация недоступна на этой установке.";
        return;
      }
      status.textContent = current.enabled
        ? `Включена. Доступно резервных кодов: ${current.recovery_codes_remaining}.` : "Выключена.";
      if (!current.enabled) {
        if (current.required) {
          status.textContent = current.pending ? "Подключение приложения ожидает подтверждения." : messages.totp_incomplete;
          if (current.pending) {
            const resume = button("Завершить настройку");
            resume.addEventListener("click", () => showCodeForm("/enable", "Подключение приложения", "Включить", "Код из приложения"));
            controls.append(resume);
          }
          return;
        }
        const start = button("Настроить");
        start.addEventListener("click", () => startEnrollment(start));
        controls.append(start);
        return;
      }
      const actions = element("div", "", "row-actions");
      const recovery = button("Выпустить новые коды");
      const disable = button("Выключить");
      const label = "Код из приложения или резервный код";
      recovery.addEventListener("click", () => showCodeForm("/recovery", "Новые резервные коды", "Выпустить", label, [
        element("p", "Предыдущие резервные коды перестанут действовать.", "muted")
      ]));
      disable.addEventListener("click", () => showCodeForm("/disable", "Выключение двухфакторной аутентификации", "Выключить", label));
      actions.append(recovery);
      if (!current.legacy_required) actions.append(disable);
      controls.append(actions);
      if (current.legacy_required) controls.append(element("p", messages.legacy_totp_required, "muted"));
    }

    try { await render(); }
    catch (error) {
      status.textContent = "";
      report(error);
    }
  }

  window.apazModules ??= {};
  window.apazModules.security = { mount };
})();
