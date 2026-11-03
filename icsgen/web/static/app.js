/* 工作台表单与进度轮询。无框架，直接用 fetch 与 DOM API。 */

(function () {
  "use strict";

  const workbench = document.getElementById("workbench");

  if (workbench) {
    initWorkbench();
  }

  const generation = document.getElementById("generation");

  if (generation) {
    initGeneration(generation);
  }

  function initWorkbench() {
    const protocolSelect = document.getElementById("protocol");
    const transportSelect = document.getElementById("transport");
    const opList = document.getElementById("op-list");
    const opFilter = document.getElementById("op-filter");
    const selectedBox = document.getElementById("selected");
    const nameInput = document.getElementById("config-name");
    const message = document.getElementById("message");

    let operations = [];
    const selected = new Map();

    protocolSelect.addEventListener("change", load);
    opFilter.addEventListener("input", renderOperations);
    document.getElementById("save").addEventListener("click", saveConfig);
    document.getElementById("generate").addEventListener("click", generate);

    async function load() {
      const response = await fetch(
        "/api/protocols/" + protocolSelect.value + "/operations"
      );
      operations = await response.json();
      selected.clear();
      renderTransports();
      renderOperations();
      renderSelected();
    }

    function renderTransports() {
      // 传输种类由 API 给出（挂在协议 option 的 data-transports 上）——
      // 按协议名硬编码会让新增协议选不到自己的传输（spec §2.2）。
      const option = protocolSelect.options[protocolSelect.selectedIndex];
      const kinds = ((option && option.dataset.transports) || "").split(",").filter(Boolean);
      transportSelect.innerHTML = "";
      for (const kind of kinds) {
        const choice = document.createElement("option");
        choice.value = kind;
        choice.textContent = kind;
        transportSelect.append(choice);
      }
    }

    function renderOperations() {
      const keyword = opFilter.value.trim().toLowerCase();
      opList.innerHTML = "";
      for (const op of operations) {
        const haystack = (op.name + " " + op.summary).toLowerCase();
        if (keyword && haystack.indexOf(keyword) === -1) {
          continue;
        }
        const row = document.createElement("label");
        row.className = "op-row";
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = selected.has(op.name);
        box.addEventListener("change", function () {
          if (box.checked) {
            selected.set(op.name, {
              op: op.name,
              variant: op.variants[0],
              params: defaultsOf(op),
              count: 1
            });
          } else {
            selected.delete(op.name);
          }
          renderSelected();
        });
        const text = document.createElement("span");
        const fc = op.func_code === null ? "" : " / FC" + op.func_code;
        text.textContent = op.summary + "（" + op.name + fc + "）";
        row.append(box, text);
        opList.append(row);
      }
    }

    function defaultsOf(op) {
      const params = {};
      const schema = op.params || {};
      for (const name of Object.keys(schema)) {
        if (schema[name].default !== undefined) {
          // 数组默认值要拷贝 —— 直接存引用会让页面内的原地修改污染共享 schema。
          const d = schema[name].default;
          params[name] = Array.isArray(d) ? d.slice() : d;
        }
      }
      return params;
    }

    function renderSelected() {
      selectedBox.innerHTML = "";
      for (const [name, item] of selected) {
        const op = operations.find(function (candidate) {
          return candidate.name === name;
        });
        const block = document.createElement("div");
        block.className = "selected-op";

        const title = document.createElement("h3");
        title.textContent = op.summary + "（" + name + "）";
        block.append(title);

        const variant = document.createElement("select");
        for (const value of op.variants) {
          const option = document.createElement("option");
          option.value = value;
          option.textContent = value;
          option.selected = value === item.variant;
          variant.append(option);
        }
        variant.addEventListener("change", function () {
          item.variant = variant.value;
        });
        block.append(field("变体", variant));

        const schema = op.params || {};
        for (const param of Object.keys(schema)) {
          const spec = schema[param];
          const input = document.createElement("input");
          input.dataset.param = param;
          if (spec.type === "integer") {
            input.type = "number";
            input.step = 1;
            if (spec.minimum !== undefined) input.min = spec.minimum;
            if (spec.maximum !== undefined) input.max = spec.maximum;
          } else {
            input.type = "text";
            if (spec.type === "array") input.placeholder = "逗号分隔的整数";
          }
          input.value = formatValue(item.params[param], spec);
          input.addEventListener("change", function () {
            const parsed = parseValue(input.value, spec);
            if (parsed === undefined) {
              delete item.params[param];
            } else {
              item.params[param] = parsed;
            }
          });
          block.append(field(param, input));
        }

        const count = document.createElement("input");
        count.type = "number";
        count.min = 1;
        count.max = 1000;
        count.value = item.count;
        count.addEventListener("change", function () {
          item.count = Number(count.value) || 1;
        });
        block.append(field("交互数量", count));

        const remove = document.createElement("button");
        remove.type = "button";
        remove.textContent = "移除";
        remove.addEventListener("click", function () {
          selected.delete(name);
          renderOperations();
          renderSelected();
        });
        block.append(remove);

        selectedBox.append(block);
      }
    }

    function field(text, control) {
      const wrap = document.createElement("label");
      wrap.className = "field";
      const span = document.createElement("span");
      span.textContent = text;
      wrap.append(span, control);
      return wrap;
    }

    function formatValue(value, spec) {
      if (value === undefined || value === null) {
        return "";
      }
      if (spec.type === "array") {
        return Array.isArray(value) ? value.join(",") : String(value);
      }
      return String(value);
    }

    function parseValue(text, spec) {
      if (text === "") {
        return undefined;
      }
      if (spec.type === "array") {
        return text
          .split(",")
          .map(function (part) { return part.trim(); })
          .filter(function (part) { return part !== ""; })
          .map(Number);
      }
      if (spec.type === "integer") {
        return Number(text);
      }
      return text;
    }

    async function collect() {
      const operations = [];
      for (const item of selected.values()) {
        const params = {};
        for (const key of Object.keys(item.params)) {
          params[key] = item.params[key];
        }
        operations.push({
          op: item.op,
          variant: item.variant,
          params: params,
          count: item.count
        });
      }
      return {
        name: nameInput.value.trim() || "未命名配置",
        protocol: protocolSelect.value,
        transport: { kind: transportSelect.value },
        operations: operations
      };
    }

    async function saveConfig() {
      const response = await fetch("/api/configs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(await collect())
      });
      const data = await response.json();
      if (!response.ok) {
        message.textContent = data.detail || "保存失败";
        return null;
      }
      message.textContent = "已保存配置 " + data.id;
      return data;
    }

    async function generate() {
      const config = await saveConfig();
      if (!config) {
        return;
      }
      const response = await fetch("/api/generations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_id: config.id })
      });
      const data = await response.json();
      if (!response.ok) {
        message.textContent = data.detail || "生成失败";
        return;
      }
      window.location.href = "/generations/" + data.generation_id;
    }

    load();
  }

  function initGeneration(root) {
    const id = root.dataset.generationId;
    const bar = document.getElementById("bar");
    const label = document.getElementById("progress-label");
    const detail = document.getElementById("detail");
    const phases = { building: "生成帧", writing: "写盘", done: "完成", failed: "失败" };

    if (root.dataset.status === "running") {
      poll();
    }

    async function poll() {
      const response = await fetch("/api/generations/" + id);
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      if (bar) {
        bar.style.width = data.percent + "%";
      }
      if (label) {
        label.textContent =
          (phases[data.phase] || data.phase) +
          " " + data.done + " / " + data.total +
          "（" + data.percent + "%）";
      }
      if (data.status === "running") {
        setTimeout(poll, 500);
      } else {
        window.location.reload();
      }
    }

    document.querySelectorAll("[data-artifact]").forEach(function (row) {
      row.addEventListener("click", async function (event) {
        // 下载链接在行内，点击它不应再触发一次产物详情请求。
        if (event.target.closest("a")) {
          return;
        }
        // 产物 id 里有 '#'，必须编码 —— 否则浏览器把它当 fragment 丢掉。
        const response = await fetch(
          "/api/generations/" + id + "/artifacts/" + encodeURIComponent(row.dataset.artifact)
        );
        if (!response.ok || !detail) {
          return;
        }
        const artifact = await response.json();
        detail.innerHTML = "";
        detail.append(frameBlock("请求帧", artifact.request));
        if (artifact.response) {
          detail.append(frameBlock("响应帧", artifact.response));
        }
      });
    });

    function frameBlock(title, frame) {
      const box = document.createElement("div");
      const heading = document.createElement("h3");
      heading.textContent = title + " — " + frame.view.summary;
      const hex = document.createElement("pre");
      hex.className = "hex";
      hex.textContent = frame.hex;
      const table = document.createElement("table");
      for (const field of frame.view.fields) {
        const row = document.createElement("tr");
        const name = document.createElement("th");
        name.textContent = field.name;
        const value = document.createElement("td");
        value.textContent = field.value;
        row.append(name, value);
        table.append(row);
      }
      box.append(heading, hex, table);
      return box;
    }
  }
})();
