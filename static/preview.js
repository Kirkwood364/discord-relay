// Live Discord-style preview: markdown subset, role mentions, attachments.
(function () {
  const input = document.getElementById("content");
  const out = document.getElementById("pv-content");
  const name = document.getElementById("pv-name");
  const avatar = document.getElementById("pv-avatar");
  const time = document.getElementById("pv-time");
  const select = document.getElementById("webhook_id");
  const counter = document.getElementById("char-count");
  const sendBtn = document.getElementById("send-btn");
  const fileInput = document.getElementById("files");
  const fileError = document.getElementById("file-error");
  const pvAttachments = document.getElementById("pv-attachments");
  const roleBar = document.getElementById("role-bar");
  const roleChips = document.getElementById("role-chips");

  const relayData = JSON.parse(document.getElementById("relay-data").textContent || "{}");
  const rolesByHook = relayData.roles || {};
  const hookInfo = relayData.hooks || {};
  const limits = relayData.limits || { maxFiles: 10, maxFileMB: 10 };
  let objectUrls = [];

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function currentRoles() {
    return rolesByHook[select.value] || [];
  }

  // Inline markdown on already-escaped text.
  function inline(s) {
    const roleName = {};
    currentRoles().forEach((r) => (roleName[r.role_id] = r.name));
    return s
      .replace(/&lt;@&amp;(\d+)&gt;/g, (m, id) =>
        roleName[id]
          ? '<span class="mention">@' + esc(roleName[id]) + "</span>"
          : '<span class="mention mention-dead" title="Not a registered role — will not ping">@unknown-role</span>'
      )
      .replace(/`([^`\n]+)`/g, "<code>$1</code>")
      .replace(/\*\*\*([^*]+)\*\*\*/g, "<strong><em>$1</em></strong>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/__([^_]+)__/g, "<u>$1</u>")
      .replace(/\*([^*\n]+)\*/g, "<em>$1</em>")
      .replace(/_([^_\n]+)_/g, "<em>$1</em>")
      .replace(/~~([^~]+)~~/g, "<s>$1</s>")
      .replace(/\|\|([^|]+)\|\|/g, '<span class="spoiler">$1</span>')
      .replace(/(https?:\/\/[^\s<]+)/g, '<span class="link">$1</span>');
  }

  function fileCount() {
    return fileInput ? fileInput.files.length : 0;
  }

  function render(text) {
    if (!text.trim()) {
      return fileCount()
        ? ""
        : '<span class="pv-placeholder">Your message will appear here as it will look in Discord.</span>';
    }
    const parts = esc(text).split(/```/);
    let html = "";
    parts.forEach((part, i) => {
      if (i % 2 === 1) {
        const body = part.replace(/^[\w+-]*\n/, "");
        html += "<pre>" + body + "</pre>";
      } else {
        const lines = part.split("\n").map((line) => {
          const m = line.match(/^(#{1,3})\s+(.*)$/);
          if (m) return "<span class='h" + m[1].length + "'>" + inline(m[2]) + "</span>";
          if (line.startsWith("&gt; ")) return "<span class='quote'>" + inline(line.slice(5)) + "</span>";
          if (line.startsWith("- ") || line.startsWith("* ")) return "<span class='li'>" + inline(line.slice(2)) + "</span>";
          return inline(line);
        });
        html += lines.join("<br>");
      }
    });
    return html;
  }

  function humanSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  function renderAttachments() {
    objectUrls.forEach((u) => URL.revokeObjectURL(u));
    objectUrls = [];
    pvAttachments.innerHTML = "";
    if (!fileInput) return true;
    const files = Array.from(fileInput.files);

    let error = "";
    if (files.length > limits.maxFiles) {
      error = "Discord allows at most " + limits.maxFiles + " attachments per message.";
    }
    const oversize = files.find((f) => f.size > limits.maxFileMB * 1024 * 1024);
    if (!error && oversize) {
      error = oversize.name + " is over the " + limits.maxFileMB + " MB limit.";
    }
    fileError.hidden = !error;
    fileError.textContent = error;

    files.forEach((f) => {
      if (f.type.startsWith("image/")) {
        const url = URL.createObjectURL(f);
        objectUrls.push(url);
        const img = document.createElement("img");
        img.src = url;
        img.alt = f.name;
        img.className = "pv-image";
        pvAttachments.appendChild(img);
      } else {
        const chip = document.createElement("div");
        chip.className = "pv-file";
        const nm = document.createElement("span");
        nm.className = "pv-file-name";
        nm.textContent = f.name;
        const sz = document.createElement("span");
        sz.className = "pv-file-size";
        sz.textContent = humanSize(f.size);
        chip.append(nm, sz);
        pvAttachments.appendChild(chip);
      }
    });
    return !error;
  }

  function renderRoleChips() {
    roleChips.innerHTML = "";
    const roles = currentRoles();
    roleBar.hidden = roles.length === 0;
    roles.forEach((r) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "role-chip";
      btn.textContent = "@" + r.name;
      btn.addEventListener("click", () => {
        const token = "<@&" + r.role_id + "> ";
        const start = input.selectionStart ?? input.value.length;
        const end = input.selectionEnd ?? input.value.length;
        input.value = input.value.slice(0, start) + token + input.value.slice(end);
        input.focus();
        input.selectionStart = input.selectionEnd = start + token.length;
        update();
      });
      roleChips.appendChild(btn);
    });
  }

  function update() {
    const filesOk = renderAttachments();
    out.innerHTML = render(input.value);
    counter.textContent = input.value.length + " / 2000";
    sendBtn.disabled = !(input.value.trim() || fileCount()) || !filesOk;
  }

  function updateIdentity() {
    const label = select.options[select.selectedIndex].text.split(" — ")[0];
    const info = hookInfo[select.value] || {};
    // Prefer the webhook's real Discord identity when we have it cached.
    name.textContent = info.name || label;
    avatar.innerHTML = "";
    if (info.avatar) {
      const img = document.createElement("img");
      img.src = info.avatar;
      img.alt = "";
      img.addEventListener("error", () => {
        avatar.innerHTML = "";
        avatar.textContent = (info.name || label).replace(/^#/, "").trim().charAt(0).toUpperCase() || "R";
      });
      avatar.appendChild(img);
    } else {
      avatar.textContent = (info.name || label).replace(/^#/, "").trim().charAt(0).toUpperCase() || "R";
    }
    renderRoleChips();
    update();
  }

  const now = new Date();
  time.textContent = "Today at " + now.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

  input.addEventListener("input", update);
  if (fileInput) fileInput.addEventListener("change", update);
  select.addEventListener("change", updateIdentity);
  updateIdentity();
})();
