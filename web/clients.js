window.apazModules ??= {};

const operationStatus = {
  unavailable: ["Управление локальными клиентами недоступно.", ""],
  idle: ["", ""],
  running: ["Выполняется операция AntiZapret…", ""],
  ok: ["Операция завершена.", "success"],
  invalid: ["Проверьте имя клиента и параметры операции.", "error"],
  conflict: ["Имя занято или уже выполняется другая операция AntiZapret.", "error"],
  failed: ["Операция AntiZapret завершилась ошибкой. Обновите список и проверьте состояние VPN.", "error"],
  timeout: ["Истекло время ожидания AntiZapret. Проверьте состояние VPN перед повтором.", "error"],
  not_configured: ["На локальном узле отсутствует конфигурация выбранного протокола или скрипт AntiZapret.", "error"]
};

window.apazModules.clients = {
  mount(root, context) {
    root.innerHTML = `
      <div class="panel upload-panel">
        <div class="upload-control">
          <button class="secondary" type="button" data-client-action="sync">Синхронизировать</button>
          <button class="secondary" type="button" data-client-action="remove" hidden>Удалить клиента</button>
          <button class="primary" type="button" data-client-action="add" hidden>Новый клиент</button>
          <input class="secondary" type="search" maxlength="64" placeholder="Поиск по имени" aria-label="Поиск по имени клиента">
        </div>
        <p class="feedback" role="status" hidden></p>
      </div>
      <div class="panel subnav" role="group" aria-label="Протоколы VPN">
        <button type="button" data-protocol="">Все</button>
        <button type="button" data-protocol="openvpn">OpenVPN</button>
        <button type="button" data-protocol="amneziawg">AmneziaWG 1.5</button>
        <button type="button" data-protocol="wireguard">WireGuard</button>
      </div>
      <div class="upload-control" data-profile-pages hidden role="group" aria-label="Страницы списка профилей">
        <button class="secondary" type="button" data-profile-previous>Назад</button>
        <span class="muted" data-profile-page></span>
        <button class="secondary" type="button" data-profile-next>Далее</button>
      </div>
      <dialog class="panel authentication" aria-labelledby="client-operation-title">
        <form method="dialog">
          <h2 id="client-operation-title"></h2>
          <label for="local-client-protocol">Протокол</label>
          <select class="secondary" id="local-client-protocol" name="protocol">
            <option value="openvpn">OpenVPN</option>
            <option value="wireguard">WireGuard / AmneziaWG 1.5</option>
          </select>
          <label for="local-client-name">Имя клиента</label>
          <input id="local-client-name" name="name" autocomplete="off" spellcheck="false" required
            maxlength="32" pattern="[A-Za-z0-9_][A-Za-z0-9_\\-]{0,31}" title="1–32 символа. Латиница, цифры, _ или -">
          <div data-certificate-days>
            <label for="local-cert-days">Срок действия сертификата, дней</label>
            <input id="local-cert-days" name="days" type="number" min="1" max="3650" value="3650" required>
          </div>
          <p class="muted" data-confirmation></p>
          <div class="form-actions">
            <button class="secondary" type="button" data-client-action="cancel">Отмена</button>
            <button class="primary" type="submit"></button>
          </div>
        </form>
      </dialog>`;

    const query = root.querySelector('input[type="search"]');
    const protocols = [...root.querySelectorAll("[data-protocol]")];
    const sync = root.querySelector('[data-client-action="sync"]');
    const add = root.querySelector('[data-client-action="add"]');
    const remove = root.querySelector('[data-client-action="remove"]');
    const feedback = root.querySelector(".feedback");
    const pagination = root.querySelector("[data-profile-pages]");
    const previous = root.querySelector("[data-profile-previous]");
    const next = root.querySelector("[data-profile-next]");
    const pageNumber = root.querySelector("[data-profile-page]");
    const dialog = root.querySelector("dialog");
    const form = root.querySelector("form");
    const protocol = form.elements.protocol;
    const clientName = form.elements.name;
    const days = form.elements.days;
    const certificate = form.querySelector("[data-certificate-days]");
    const confirmation = form.querySelector("[data-confirmation]");
    const submit = form.querySelector('button[type="submit"]');
    let selectedProtocol = new URLSearchParams(location.search).get("protocol") || "";
    if (!protocols.some(button => button.dataset.protocol === selectedProtocol)) selectedProtocol = "";
    let revision;
    let requestRevision;
    let action;
    let timer;
    let queryTimer;
    let available = false;
    let busy = false;
    let page = { offset: 0, cursor: "" };
    let nextPage;
    const previousPages = [];

    function profileFilter() {
      return { query: query.value.trim(), protocol: selectedProtocol };
    }

    function resetPages() {
      page = { offset: 0, cursor: "" };
      nextPage = undefined;
      previousPages.length = 0;
      pagination.hidden = true;
    }

    function filter() {
      resetPages();
      return context.filterProfiles(profileFilter());
    }

    async function loadPage(target) {
      previous.disabled = next.disabled = true;
      page = target;
      await context.reloadProfiles(page.offset, page.cursor, profileFilter());
    }

    root.addEventListener("apaz:profile-page", event => {
      const { offset, next_offset: nextOffset, next_cursor: nextCursor } = event.detail;
      if (offset !== page.offset) return;
      nextPage = Number.isSafeInteger(nextOffset) && typeof nextCursor === "string" ?
        { offset: nextOffset, cursor: nextCursor } : undefined;
      previous.disabled = previousPages.length === 0;
      next.disabled = !nextPage;
      pagination.hidden = previous.disabled && next.disabled;
      pageNumber.textContent = "Страница " + (previousPages.length + 1);
    }, { signal: context.signal });
    previous.addEventListener("click", () => {
      if (previousPages.length) loadPage(previousPages.pop());
    }, { signal: context.signal });
    next.addEventListener("click", () => {
      if (!nextPage) return;
      previousPages.push(page);
      loadPage(nextPage);
    }, { signal: context.signal });

    function search() {
      clearTimeout(queryTimer);
      queryTimer = setTimeout(filter, 175);
    }

    function show(message, kind = "") {
      feedback.hidden = !message;
      feedback.textContent = message;
      feedback.dataset.kind = kind;
    }

    function updateButtons() {
      add.hidden = remove.hidden = !available;
      add.disabled = remove.disabled = busy;
    }

    function schedule() {
      clearTimeout(timer);
      timer = setTimeout(checkOperation, 1000);
    }

    function applyStatus(status) {
      busy = status === "running";
      available = status !== "unavailable" && revision !== undefined;
      show(...(operationStatus[status] || operationStatus.failed));
      updateButtons();
      if (busy) schedule();
      if (status === "ok") filter();
    }

    async function checkOperation() {
      try {
        const response = await context.api("/api/clients/operation");
        const data = await response.json();
        if (!context.signal.aborted) applyStatus(response.ok || data.status ? data.status : "unavailable");
      } catch {
        if (context.signal.aborted) return;
        show("Нет связи с панелью. Запрос состояния повторится.", "error");
        schedule();
      }
    }

    async function loadContext() {
      available = false;
      revision = undefined;
      updateButtons();
      try {
        const response = await context.api("/api/nodes/active");
        const node = response.ok ? await response.json() : {};
        if (context.signal.aborted) return;
        if (node.active_node_id !== 0 || !Number.isSafeInteger(node.revision)) {
          show(node.name ? "Для удалённого узла операции с клиентами недоступны." : operationStatus.unavailable[0]);
          return;
        }
        revision = node.revision;
        await checkOperation();
      } catch {
        if (!context.signal.aborted) show(operationStatus.unavailable[0]);
      }
    }

    function updateDialog() {
      const isAdd = action === "add";
      const isOpenVPN = protocol.value === "openvpn";
      certificate.hidden = days.disabled = !isAdd || !isOpenVPN;
      confirmation.textContent = !isAdd
        ? "Доступ клиента для выбранного протокола будет отозван."
        : isOpenVPN ? "Будет создан клиент OpenVPN." : "Будет создан клиент WireGuard с профилями AmneziaWG 1.5.";
    }

    function openDialog(operation) {
      if (busy || !available || revision === undefined) return;
      action = operation;
      requestRevision = revision;
      form.reset();
      clientName.setCustomValidity("");
      protocol.value = ["wireguard", "amneziawg"].includes(selectedProtocol) ? "wireguard" : "openvpn";
      form.querySelector("h2").textContent = action === "add" ? "Новый клиент" : "Удалить клиента";
      submit.textContent = action === "add" ? "Создать" : "Удалить";
      updateDialog();
      dialog.showModal();
      clientName.focus();
    }

    form.addEventListener("submit", async event => {
      event.preventDefault();
      if (busy || requestRevision === undefined) return;
      const name = clientName.value;
      if (action === "add" && /^(vpn-|antizapret-)/i.test(name)) {
        clientName.setCustomValidity("Выберите имя без префикса vpn- или antizapret-.");
        clientName.reportValidity();
        return;
      }
      const body = new URLSearchParams({ operation: `${protocol.value}-${action}`, name, revision: requestRevision });
      if (!days.disabled) body.set("days", days.value);
      dialog.close();
      busy = true;
      updateButtons();
      show(operationStatus.running[0]);
      try {
        const response = await context.api("/api/clients/operation", { method: "POST", body });
        const data = await response.json();
        if (context.signal.aborted) return;
        if (response.status === 409 && !data.status) {
          await loadContext();
          if (!context.signal.aborted) show("Активный узел изменился. Проверьте выбранный узел и повторите операцию.", "error");
          return;
        }
        applyStatus(data.status || "failed");
      } catch {
        if (!context.signal.aborted) {
          show("Не удалось подтвердить запуск. Проверяем состояние операции…", "error");
          schedule();
        }
      }
    }, { signal: context.signal });

    for (const button of protocols) {
      button.setAttribute("aria-pressed", String(button.dataset.protocol === selectedProtocol));
      button.addEventListener("click", () => {
        if (selectedProtocol !== button.dataset.protocol)
          context.navigate(button.dataset.protocol ? `/?protocol=${button.dataset.protocol}` : "/");
      }, { signal: context.signal });
    }
    query.addEventListener("input", search, { signal: context.signal });
    clientName.addEventListener("input", () => clientName.setCustomValidity(""), { signal: context.signal });
    protocol.addEventListener("change", updateDialog, { signal: context.signal });
    sync.addEventListener("click", async () => {
      sync.disabled = true;
      try { await filter(); }
      finally { if (!context.signal.aborted) sync.disabled = false; }
    }, { signal: context.signal });
    add.addEventListener("click", () => openDialog("add"), { signal: context.signal });
    remove.addEventListener("click", () => openDialog("remove"), { signal: context.signal });
    form.querySelector('[data-client-action="cancel"]').addEventListener("click", () => dialog.close(), { signal: context.signal });
    context.signal.addEventListener("abort", () => {
      clearTimeout(timer);
      clearTimeout(queryTimer);
      if (dialog.open) dialog.close();
    }, { once: true });
    filter();
    if (context.identity?.role === "admin") loadContext();
  }
};
