const telegramOrigin = "https://oauth.telegram.org";
const botName = /^[a-z][a-z0-9_]{1,28}bot$/i;

function node(tag, label, className = "") {
  const element = document.createElement(tag);
  if (label) element.textContent = label;
  if (className) element.className = className;
  return element;
}

function button(label, className = "secondary") {
  const control = node("button", label, className);
  control.type = "button";
  return control;
}

function notice() {
  const output = node("p", "", "feedback");
  output.setAttribute("role", "status");
  output.hidden = true;
  return output;
}

function report(output, text, kind = "") {
  output.hidden = !text;
  output.textContent = text;
  output.dataset.kind = kind;
}

function input(container, label, attributes) {
  const element = document.createElement("input");
  Object.assign(element, attributes);
  const field = node("label", label);
  field.htmlFor = element.id;
  container.append(field, element);
  return element;
}

function switchInput(container, text, checked) {
  const label = node("label");
  const control = document.createElement("input");
  control.type = "checkbox";
  control.checked = checked;
  label.append(control, " " + text);
  container.append(label);
  return control;
}

const errors = {
  telegram_login_failed: "Telegram не подтвердил вход. Проверьте привязку, код и повторите попытку.",
  telegram_already_linked: "Этот Telegram ID уже привязан к учётной записи.",
  telegram_disabled: "Вход через Telegram выключен.",
  invalid_telegram_form: "Проверьте имя бота, токен и время действия авторизации.",
  too_many_attempts: "Слишком много попыток. Повторите позже.",
  unauthorized: "Войдите в панель, чтобы продолжить.",
  admin_required: "Войдите как администратор."
};

async function request(context, route, options = {}) {
  const response = await context.api("/api/telegram/" + route, options);
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(errors[result.error] || "Не удалось выполнить операцию с Telegram.");
    error.code = result.error;
    throw error;
  }
  return result;
}

function statusMessage(error) {
  return error instanceof TypeError ? "Нет связи с панелью." : error.message;
}

function widgetAuthPayload(user) {
  if (!user || typeof user !== "object" || Array.isArray(user)) return "";
  const fields = Object.entries(user);
  if (fields.length > 64 || typeof user.hash !== "string") return "";
  const data = new URLSearchParams();
  for (const [key, value] of fields) {
    if (!/^[a-zA-Z0-9_]{1,64}$/.test(key) ||
      !(typeof value === "string" || Number.isSafeInteger(value))) return "";
    data.set(key, String(value));
  }
  return data.toString();
}

function widget(username, target, signal, onProof) {
  if (!botName.test(username) || signal.aborted) return;
  const frame = node("iframe");
  const url = new URL("/embed/" + username, telegramOrigin);
  url.search = new URLSearchParams({
    origin: location.origin,
    return_to: location.origin + location.pathname,
    size: "medium",
    userpic: "false",
    lang: "ru"
  });
  frame.title = "Telegram Login Widget";
  frame.sandbox = "allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox";
  frame.referrerPolicy = "origin";
  frame.width = "200";
  frame.height = "38";
  frame.style.border = "0";
  frame.src = url.href;

  function notify(event, fields) {
    frame.contentWindow?.postMessage(JSON.stringify({ event, ...fields }), telegramOrigin);
  }
  window.addEventListener("message", (event) => {
    if (event.origin !== telegramOrigin || event.source !== frame.contentWindow ||
      typeof event.data !== "string" || event.data.length > 8192) return;
    let message;
    try { message = JSON.parse(event.data); }
    catch { return; }
    if (message?.event === "ready") {
      notify("visible", { frame: "telegram-login-" + username });
      notify("focus", { has_focus: document.hasFocus() });
    }
    if (message?.event === "resize") {
      if (Number.isInteger(message.width) && message.width >= 100 && message.width <= 300) frame.width = String(message.width);
      if (Number.isInteger(message.height) && message.height >= 20 && message.height <= 70) frame.height = String(message.height);
    }
    if (message?.event === "auth_user" && !message.init) {
      const proof = widgetAuthPayload(message.auth_data);
      if (proof) onProof(proof);
    }
  }, { signal });
  for (const event of ["focus", "blur"]) {
    window.addEventListener(event, () => notify("focus", { has_focus: document.hasFocus() }), { signal });
  }
  signal.addEventListener("abort", () => frame.remove(), { once: true });
  target.replaceChildren(frame);
}

function widgetControl(label, username, signal, onProof) {
  const wrapper = node("div", "", "telegram-widget");
  const trigger = button(label);
  trigger.addEventListener("click", () => widget(username, wrapper, signal, onProof), { once: true });
  wrapper.append(trigger);
  return wrapper;
}

async function mountLogin(root, context) {
  root.replaceChildren();
  let config;
  try { config = await request(context, "config"); }
  catch { return; }
  if (context.signal.aborted || !config.enabled || !botName.test(config.bot_username)) return;

  const errorOutput = notice();
  const factor = node("form");
  factor.hidden = true;
  const secondFactor = node("div");
  secondFactor.hidden = true;
  const code = input(secondFactor, "Код приложения или резервный код", {
    id: "telegram-login-code", autocomplete: "one-time-code", maxLength: 8
  });
  const captcha = node("div");
  captcha.hidden = true;
  const image = node("img");
  image.alt = "Проверочный код";
  const refresh = button("Обновить код");
  captcha.append(image, refresh);
  const answer = input(captcha, "Введите проверочный код", { id: "telegram-captcha", autocomplete: "off", maxLength: 12 });
  const submit = button("Продолжить", "primary");
  submit.type = "submit";
  factor.append(secondFactor, captcha, submit);
  let proof = "";
  let captchaId = "";
  let working = false;

  function resetCaptcha() {
    captchaId = "";
    captcha.hidden = true;
    answer.required = false;
    answer.value = "";
    image.removeAttribute("src");
  }

  async function challenge(focus = false) {
    resetCaptcha();
    refresh.disabled = true;
    try {
      const response = await context.api("/api/auth/captcha");
      const result = response.ok ? await response.json() : {};
      if (context.signal.aborted) return;
      if (!/^[0-9a-f]{32}$/i.test(result.id) || !/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(result.image)) {
        if (response.status !== 404) throw new Error("Не удалось загрузить проверочный код. Попробуйте позже.");
        return;
      }
      captchaId = result.id;
      image.src = result.image;
      captcha.hidden = false;
      factor.hidden = false;
      answer.required = true;
      if (focus) answer.focus();
    } catch (error) {
      if (!context.signal.aborted) report(errorOutput, statusMessage(error), "error");
    } finally {
      refresh.disabled = false;
    }
  }

  async function signIn() {
    if (working || !proof || context.signal.aborted) return;
    working = true;
    submit.disabled = true;
    report(errorOutput, "");
    const body = new URLSearchParams({ mode: "widget", data: proof });
    if (!secondFactor.hidden) body.set("code", code.value.trim());
    if (captchaId) {
      body.set("captcha_id", captchaId);
      body.set("captcha_answer", answer.value.trim());
    }
    try {
      const identity = await request(context, "login", { method: "POST", body });
      if (!context.signal.aborted) {
        proof = "";
        code.value = "";
        context.onLogin(identity);
      }
    } catch (error) {
      if (!context.signal.aborted) {
        if (error.code === "second_factor_required") {
          factor.hidden = false;
          secondFactor.hidden = false;
          code.required = true;
          code.focus();
          if (captchaId) await challenge();
        } else if (error.code === "captcha_required") {
          await challenge(true);
        } else {
          report(errorOutput, statusMessage(error), "error");
          if (captchaId) await challenge();
        }
      }
    } finally {
      working = false;
      submit.disabled = false;
    }
  }

  const control = widgetControl("Войти через Telegram", config.bot_username, context.signal, (value) => {
    if (!working) {
      factor.hidden = true;
      secondFactor.hidden = true;
      code.required = false;
      code.value = "";
      resetCaptcha();
      proof = value;
      signIn();
    }
  });
  factor.addEventListener("submit", (event) => {
    event.preventDefault();
    signIn();
  });
  refresh.addEventListener("click", () => challenge(true));
  context.signal.addEventListener("abort", () => { proof = ""; root.replaceChildren(); }, { once: true });
  root.append(control, factor, errorOutput);
}

async function mountBinding(root, context, config) {
  const box = node("section", "", "panel upload-panel");
  box.append(node("h2", "Моя учётная запись Telegram"));
  const output = notice();
  const value = node("p", "Загрузка…", "muted");
  const controls = node("div");
  root.append(box);
  box.append(value, controls, output);

  let busy = false;
  let widgetController;
  root.addEventListener("telegram-reset", () => widgetController?.abort(), { once: true, signal: context.signal });
  function render(binding) {
    widgetController?.abort();
    controls.replaceChildren();
    if (binding.telegram_id) {
      value.textContent = "Telegram ID " + binding.telegram_id;
      const unlink = button("Отвязать");
      unlink.addEventListener("click", () => {
        if (window.confirm("Отвязать Telegram и завершить остальные сеансы панели?"))
          update("unlink");
      });
      controls.append(unlink);
    } else {
      value.textContent = "Telegram не привязан.";
      if (config.enabled) {
        widgetController = new AbortController();
        const signal = AbortSignal.any([context.signal, widgetController.signal]);
        controls.append(widgetControl("Подтвердить Telegram ID", config.bot_username, signal,
          (proof) => update("link", new URLSearchParams({ mode: "widget", data: proof }))));
      }
    }
  }

  async function update(route, body) {
    if (busy) return;
    busy = true;
    report(output, "");
    try {
      const binding = await request(context, route, { method: "POST", body });
      if (!context.signal.aborted) render(binding);
    } catch (error) {
      if (!context.signal.aborted) report(output, statusMessage(error), "error");
    } finally { busy = false; }
  }

  try {
    const binding = await request(context, "status");
    if (!context.signal.aborted) render(binding);
  } catch (error) {
    if (!context.signal.aborted) {
      value.hidden = true;
      report(output, statusMessage(error), "error");
    }
  }
}

function mountSettings(root, context, config, bindingRoot) {
  const form = node("form", "", "panel upload-panel telegram-settings");
  form.append(node("h2", "Вход через Telegram"));
  const username = input(form, "Имя бота", {
    id: "telegram-bot-username", value: config.bot_username, maxLength: 33, autocomplete: "off", spellcheck: false
  });
  const token = input(form, "Новый токен бота", {
    id: "telegram-bot-token", type: "password", autocomplete: "new-password", maxLength: 256
  });
  const tokenStatus = node("p", config.bot_token_set ? "Токен сохранён." : "Токен ещё не сохранён.", "muted");
  form.append(tokenStatus);
  const age = input(form, "Время действия авторизации, секунд", {
    id: "telegram-expiry", type: "number", min: "30", max: "86400", step: "1",
    value: String(config.auth_max_age_seconds), required: true
  });
  const legacy = switchInput(form, "Разрешить вход через Telegram Login Widget", config.legacy_login_enabled);
  const save = button("Сохранить", "primary");
  save.type = "submit";
  const clear = button("Удалить токен");
  clear.disabled = !config.bot_token_set;
  const output = notice();
  const actions = node("div", "", "telegram-actions");
  actions.append(save, clear);
  form.append(actions, output);
  root.prepend(form);

  async function update(remove = false) {
    const body = new URLSearchParams({
      bot_username: username.value.trim(), auth_max_age_seconds: age.value,
      legacy_login_enabled: String(!remove && legacy.checked), mini_enabled: String(!remove && config.mini_enabled)
    });
    if (remove || token.value.trim()) body.set("bot_token", remove ? "" : token.value.trim());
    save.disabled = true;
    clear.disabled = true;
    report(output, "");
    try {
      config = await request(context, "settings", { method: "POST", body });
      if (context.signal.aborted) return;
      legacy.checked = config.legacy_login_enabled;
      token.value = "";
      tokenStatus.textContent = config.bot_token_set ? "Токен сохранён." : "Токен ещё не сохранён.";
      report(output, "Настройки сохранены.", "success");
      const current = await request(context, "config");
      if (!context.signal.aborted) {
        bindingRoot.dispatchEvent(new Event("telegram-reset"));
        bindingRoot.replaceChildren();
        mountBinding(bindingRoot, context, current);
      }
    } catch (error) {
      if (!context.signal.aborted) report(output, statusMessage(error), "error");
    } finally {
      save.disabled = false;
      clear.disabled = !config.bot_token_set;
    }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); update(); });
  clear.addEventListener("click", () => {
    if (window.confirm("Удалить токен и отключить вход через Telegram?")) update(true);
  });
}

async function mount(root, context) {
  root.replaceChildren();
  const output = notice();
  root.append(output);
  try {
    const config = await request(context, "config");
    if (context.signal.aborted) return;
    const binding = node("div");
    root.append(binding);
    mountBinding(binding, context, config);
    if (context.identity?.role === "admin") {
      const settings = await request(context, "settings");
      if (!context.signal.aborted) mountSettings(root, context, settings, binding);
    }
  } catch (error) {
    if (!context.signal.aborted) report(output, statusMessage(error), "error");
  }
}

window.apazModules ??= {};
window.apazModules.telegram = { mount, mountLogin };
