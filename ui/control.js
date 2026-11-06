const token = location.hash.slice(1);
history.replaceState(null, "", location.pathname);
let snapshot = null;
const notice = document.querySelector("#notice");
const content = document.querySelector("#content");
const sections = {
  Setup: "Follow the first-run checklist. Each step shows its current status and the action that fixes it.",
  Discord: "Manage the owner, channel, and bot identities used by this installation.",
  Credentials: "Save credentials in this installation’s OS credential store. Saved values are never displayed back.",
  Providers: "Choose models and reasoning effort, and check each provider CLI and sign-in.",
  Connections: "Add, test and sign in to MCP connections. Connecting or discovering never authorizes a tool.",
  Memory: "Configure bounded memory aliases and delivery scopes.",
  Access: "Choose the enabled roster and allowed users.",
  Privacy: "Curate public context, choose the privacy source, and preview redaction.",
  Limits: "Set queue sizes, request deadlines, quotas, and discussion length.",
  Services: "Start, stop and restart services, watch health and logs, and manage recovery.",
  Diagnostics: "Run preflight, provider checks and an optional test message.",
  Backup: "Export or import non-secret settings. Credentials are never included.",
};
const STEP_TITLES = {
  venv: "Python virtual environment", dependencies: "Pinned Python dependencies",
  identities: "Discord identities", node: "Node.js", pm2: "Checkout-local PM2",
  codex_cli: "Codex CLI", claude_cli: "Claude Code CLI",
  CODEXBOT_TOKEN: "CodexBot token", ANTIGRAVITYBOT_TOKEN: "AntigravityBot token",
  CLAUDEBOT_TOKEN: "ClaudeBot token", GEMINI_API_KEY: "Gemini API key",
  CLAUDE_CODE_OAUTH_TOKEN: "Claude OAuth token", preflight: "Preflight",
};
const CREDENTIAL_LABELS = {
  CODEXBOT_TOKEN: "CodexBot Discord token", ANTIGRAVITYBOT_TOKEN: "AntigravityBot Discord token",
  CLAUDEBOT_TOKEN: "ClaudeBot Discord token", GEMINI_API_KEY: "Gemini API key",
  CLAUDE_CODE_OAUTH_TOKEN: "Claude OAuth token",
};
const ROLE_TOKEN = {codex: "CODEXBOT_TOKEN", antigravity: "ANTIGRAVITYBOT_TOKEN", claude: "CLAUDEBOT_TOKEN"};
const ROLE_LABEL = {codex: "CodexBot", antigravity: "AntigravityBot", claude: "ClaudeBot"};
const PROFILE_TEMPLATES = {
  http: {transport: "http", endpoint: "https://", protocol: "2026-07-28", authentication: {type: "none"}},
  stdio: {transport: "stdio", command: "", arguments: [], cwd: "", environment: {}, credentials: {}},
};

function showNotice(text, error = false) {
  notice.textContent = text;
  notice.className = error ? "error" : "";
}

async function api(path, data) {
  const response = await fetch("/api/" + path, {
    method: data ? "POST" : "GET",
    headers: { Authorization: "Bearer " + token, ...(data ? {"Content-Type": "application/json"} : {}) },
    ...(data ? {body: JSON.stringify(data)} : {}),
    cache: "no-store",
  });
  if (!response.ok) {
    if (response.status === 403) throw new Error("Session unavailable. Reopen the control window from the launcher.");
    let message = "Request refused. Check the values and reload if another editor changed them.";
    try { message = (await response.json()).error || message; } catch { /* keep generic text */ }
    throw new Error(message);
  }
  return response.json();
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function card(title) {
  const node = element("div", "", "card");
  node.append(element("h2", title));
  content.append(node);
  return node;
}

function button(parent, title, action, secondary = false) {
  const node = element("button", title, secondary ? "secondary" : "");
  node.type = "button";
  node.addEventListener("click", async () => {
    node.disabled = true;
    try { await action(); } catch (error) { showNotice(error.message, true); }
    finally { node.disabled = false; }
  });
  parent.append(node);
  return node;
}

function actions(parent) {
  const node = element("div", "", "actions");
  parent.append(node);
  return node;
}

function textInput(parent, label, value = "", multiline = false) {
  const id = "field-" + crypto.randomUUID();
  const title = element("label", label);
  title.htmlFor = id;
  const input = element(multiline ? "textarea" : "input");
  input.id = id;
  input.value = value;
  parent.append(title, input);
  return input;
}

function checkbox(parent, label) {
  const input = textInput(parent, label);
  input.type = "checkbox";
  input.classList.add("toggle");
  return input;
}

function secretInput(parent, label) {
  const input = textInput(parent, label);
  input.type = "password";
  input.autocomplete = "off";
  input.spellcheck = false;
  return input;
}

function pill(parent, text, good) {
  const node = element("span", text.replaceAll("_", " "), "pill " + (good === true ? "good" : good === false ? "bad" : ""));
  parent.append(node);
  return node;
}

function since(seconds) {
  if (seconds === null || seconds === undefined) return "never";
  return seconds < 120 ? Math.round(seconds) + " s ago" : Math.round(seconds / 60) + " min ago";
}

function stamp(epoch) {
  return epoch ? new Date(epoch * 1000).toLocaleString() : "never";
}

async function reload() {
  snapshot = await api("config");
}

function typedEditor(section) {
  const box = card(section + " settings");
  const entries = {};
  const labels = {
    owner_id: "Owner ID", channel_id: "Channel ID", codex_id: "CodexBot ID",
    antigravity_id: "AntigravityBot ID", claude_id: "ClaudeBot ID",
    codex: "Enable CodexBot", antigravity: "Enable AntigravityBot", claude: "Enable ClaudeBot",
    allowed_user_ids: "Allowed user IDs, separated by commas",
    allow_work: "Allow private owner work",
    gemini_model: "Gemini model", codex_model: "Codex model",
    codex_reasoning_effort: "Codex reasoning effort",
    queue_capacity: "Queue capacity", max_turns: "Maximum discussion turns (1–15)",
    request_seconds: "Provider request deadline (seconds)",
    total_request_seconds: "Total request deadline (seconds)",
  };
  for (const [key, field] of Object.entries(snapshot.forms[section])) {
    const label = labels[key] || key.replaceAll("_", " ");
    const input = textInput(box, label, field.value);
    if (field.kind === "toggle") {
      input.type = "checkbox";
      input.checked = field.value;
      input.classList.add("toggle");
    }
    if (field.kind === "integer" || field.kind === "id") input.inputMode = "numeric";
    entries[key] = input;
  }
  let risk = null;
  if (section === "Access") risk = checkbox(box, "I understand that owner work grants broader local access.");
  button(box, "Save changes", async () => {
    const value = Object.fromEntries(Object.entries(entries).map(([key, input]) => [
      key, input.type === "checkbox" ? input.checked : input.value,
    ]));
    await api("save", {
      name: "bridge_config.json", section, value, typed: true,
      revision: snapshot.revisions["bridge_config.json"], confirm_work: risk !== null && risk.checked,
    });
    await reload();
    showNotice("Saved and verified. Restart the affected services to apply runtime changes.");
  });
  if (section === "Discord") {
    const invites = card("Invite the bots");
    invites.append(element("p", "Enable Message Content Intent in Discord Developer Portal. These links request View Channel, Send Messages and Read Message History, never Administrator.", "help"));
    for (const role of ["codex", "antigravity", "claude"]) {
      const link = element("a", labels[role + "_id"].replace(" ID", ""));
      link.href = "https://discord.com/oauth2/authorize?scope=bot&permissions=68608&client_id=" + snapshot.forms.Discord[role + "_id"].value;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      invites.append(link);
    }
  }
}

function editor(title, name, value, section = null) {
  const box = card(title);
  const input = textInput(box, title, value, true);
  let risk = null;
  if (section === "Access") risk = checkbox(box, "I authorize owner work to grant broader local access.");
  button(box, "Save changes", async () => {
    const confirm_work = risk !== null && risk.checked;
    await api("save", {name, value: input.value, section, revision: snapshot.revisions[name], confirm_work});
    await reload();
    showNotice("Saved and verified. Restart the affected services to apply runtime changes.");
  });
}

async function renderSetup() {
  const status = await api("checklist");
  const list = card("First-run checklist");
  list.append(element("p", status.ready ? "Every required step is complete. Run preflight, then start services." : "Complete the steps marked Action needed, in order.", "help"));
  const table = element("ul", "", "steps");
  for (const step of status.steps) {
    const row = element("li");
    row.append(element("span", STEP_TITLES[step.id] || step.id, "step"));
    pill(row, step.state === "action" ? "action needed" : step.state, step.state === "ok" ? true : step.state === "action" ? false : null);
    if (step.state !== "ok" && step.state !== "not_needed") {
      if (step.fix.command) row.append(element("code", step.fix.command));
      if (step.fix.screen) button(row, "Open " + step.fix.screen, () => render(step.fix.screen), true);
      if (step.fix.action) {
        const label = step.fix.action === "preflight" ? "Run preflight" : "Install";
        button(row, label, async () => {
          showNotice("Running… this can take several minutes.");
          const result = await api("checklist", {action: step.fix.action});
          await render("Setup");
          showNotice(result.preflight ? "Preflight " + result.preflight + "." : "Installed " + result.installed + ".");
        }, true);
      }
    }
    table.append(row);
  }
  list.append(table);
  if (status.steps.some(step => step.id === "identities" && step.state === "action")) {
    const box = card("Discord identities");
    box.append(element("p", "Create the three applications in Discord Developer Portal. Enable Message Content Intent and grant only the channel permissions the bots need.", "help"));
    const entries = {};
    for (const [key, label] of Object.entries({owner_id:"Owner ID",channel_id:"Channel ID",codex_id:"CodexBot ID",antigravity_id:"AntigravityBot ID",claude_id:"ClaudeBot ID"})) {
      entries[key] = textInput(box, label);
      entries[key].inputMode = "numeric";
    }
    button(box, "Create local configuration", async () => {
      const data = Object.fromEntries(Object.entries(entries).map(([key,input]) => [key, input.value.trim()]));
      if (Object.values(data).some(value => !/^[1-9][0-9]*$/.test(value))) throw new Error("Enter valid numeric Discord IDs.");
      await api("setup", data);
      await reload();
      await render("Setup");
      showNotice("Local configuration created. Continue with credentials and provider setup.");
    });
  }
}

async function renderCredentials() {
  const state = await api("credentials");
  const providers = (await api("providers")).providers;
  const sources = {};
  for (const entry of Object.values(providers)) Object.assign(sources, entry.credentials);
  for (const [name, status] of Object.entries(state.credentials)) {
    const box = card(CREDENTIAL_LABELS[name]);
    const line = element("p", "", "help");
    line.append("OS store: ");
    pill(line, status, status === "set");
    const effective = sources[name];
    if (effective) {
      line.append(" In use: " + (effective.source === "native" ? "OS store" : "environment fallback") + " (");
      pill(line, effective.state, effective.state === "set");
      line.append(") · last verified " + stamp(effective.verified));
    }
    box.append(line);
    const input = secretInput(box, "New value");
    const row = actions(box);
    button(row, "Save credential", async () => {
      const value = input.value;
      input.value = "";
      await api("credentials", {action: "set", name, value, revision: state.revision});
      await reload();
      await render("Credentials");
      showNotice("Credential saved and verified in the OS store. Restart the affected services.");
    });
    if (name !== "CLAUDE_CODE_OAUTH_TOKEN") {
      button(row, "Verify", async () => {
        const result = await api("providers", {action: "verify", target: name});
        await render("Credentials");
        showNotice("Verification " + result.check.replaceAll("_", " ") + ".", result.check !== "passed");
      }, true);
    }
    button(row, "Remove stored credential", async () => {
      if (!confirm("Remove this credential from the installation’s OS store?")) return;
      await api("credentials", {action: "delete", name, revision: state.revision});
      await reload();
      await render("Credentials");
      showNotice("Stored credential removed.");
    }, true);
  }
  const fallback = card("Environment fallback");
  fallback.append(element("p", "A credential that is not saved here is read from the process or Windows User environment under the name shown above, as in the CLI setup. Saving a value here selects the OS store explicitly for that name.", "help"));
}

async function renderProviders() {
  typedEditor("Providers");
  const data = (await api("providers")).providers;
  for (const [role, entry] of Object.entries(data)) {
    const box = card(ROLE_LABEL[role] + (role === "antigravity" ? " (Gemini)" : role === "codex" ? " (Codex CLI)" : " (Claude Code CLI)"));
    const line = element("p", "", "help");
    pill(line, entry.enabled ? "enabled" : "disabled", entry.enabled);
    if (entry.model !== undefined) line.append(" Model: " + (entry.model || "provider default"));
    if (entry.reasoning_effort) line.append(" · effort " + entry.reasoning_effort);
    if (entry.pinned) {
      line.append(" · CLI " + (entry.installed || "not installed") + " (pinned " + entry.pinned + ") ");
      pill(line, entry.installed === entry.pinned ? "pinned" : "install needed", entry.installed === entry.pinned);
    }
    box.append(line);
    if (!entry.pinned) continue;
    const row = actions(box);
    button(row, "Install pinned CLI", async () => {
      showNotice("Installing… this can take several minutes.");
      await api("checklist", {action: "install_" + role});
      await render("Providers");
      showNotice("Installed the pinned " + ROLE_LABEL[role] + " CLI.");
    }, true);
    button(row, "Check sign-in", async () => {
      const result = await api("providers", {action: "login", target: role});
      showNotice(ROLE_LABEL[role] + " CLI: " + result.login.replaceAll("_", " ") + ".", result.login !== "signed_in");
    }, true);
    const command = role === "codex"
      ? "node tools/codex-cli/node_modules/@openai/codex/bin/codex.js login"
      : "node tools/claude-cli/node_modules/@anthropic-ai/claude-code/cli.js setup-token";
    box.append(element("p", role === "codex" ? "Sign in with your own account in a terminal:" : "Create a subscription token in a terminal, then paste it into Credentials → Claude OAuth token. The token is never shown here:", "help"), element("code", command));
  }
}

function profileFields(box, value) {
  const kind = element("select");
  for (const option of ["http", "stdio"]) {
    const node = element("option", option === "http" ? "Remote HTTP" : "Local stdio command");
    node.value = option;
    kind.append(node);
  }
  const input = textInput(box, "Profile (JSON; credentials are references, never values)", JSON.stringify(value || PROFILE_TEMPLATES.http, null, 2), true);
  input.classList.add("short");
  if (!value) {
    const label = element("label", "Transport");
    box.insertBefore(label, input.previousSibling);
    box.insertBefore(kind, input.previousSibling);
    kind.addEventListener("change", () => { input.value = JSON.stringify(PROFILE_TEMPLATES[kind.value], null, 2); });
  }
  return input;
}

async function renderConnections() {
  const data = await api("connections");
  const run = async (action, name, extra = {}) => {
    const result = await api("connections", {action, name, ...extra});
    await render("Connections");
    return result;
  };
  if (!data.enabled) {
    const off = card("Capabilities are disabled");
    off.append(element("p", "Connections can be configured and tested, but no Discord command can use them until capabilities are enabled in the policy below.", "help"));
  }
  for (const server of data.servers) {
    const box = card(server.id);
    const line = element("p", "", "help");
    line.append(server.transport === "http" ? "Remote HTTP · " : "Local stdio · ");
    pill(line, server.connected ? "connected" : server.outcome, server.connected ? true : ["failed", "exited", "rejected"].includes(server.outcome) ? false : null);
    line.append(" Authentication: ");
    pill(line, server.authentication, ["configured", "none"].includes(server.authentication) ? true : ["required", "expired", "unavailable"].includes(server.authentication) ? false : null);
    box.append(line);
    const tools = element("p", server.tools.length ? "Authorized tools: " + server.tools.map(t => t.alias + " → " + t.name + " (users " + t.user_ids.join(", ") + "; bots " + t.bot_ids.join(", ") + ")").join("; ") : "No tools are authorized for this connection.", "help");
    box.append(tools);
    const found = element("div", "", "result");
    found.hidden = true;
    const row = actions(box);
    button(row, "Test", async () => {
      const result = await run("test", server.id);
      showNotice(server.id + ": " + result.outcome.replaceAll("_", " ") + ".");
    }, true);
    button(row, "Discover tools", async () => {
      const result = await api("connections", {action: "discover", name: server.id});
      found.hidden = false;
      found.textContent = result.tools.map(t => t.name + (t.authorized ? " — authorized" : " — not authorized")).join("\n") || "No tools offered.";
      showNotice("Discovery never authorizes tools. Add authorizations in the policy below.");
    }, true);
    button(row, server.connected ? "Disconnect" : "Connect", async () => {
      await run(server.connected ? "disconnect" : "connect", server.id);
      showNotice(server.connected ? "Disconnected." : "Connected. This test session does not change the bots.");
    }, true);
    if (server.oauth) {
      button(row, "Sign in", async () => {
        showNotice("Complete sign-in in the browser window that opened.");
        await run("signin", server.id);
        showNotice("Signed in. Tokens are stored in the OS credential store.");
      }, true);
      button(row, "Log out", async () => {
        const result = await run("logout", server.id);
        showNotice("Logged out (" + result.revocation.replaceAll("_", " ") + ").");
      }, true);
    }
    box.append(found);
    for (const reference of server.oauth ? [] : server.references) {
      const status = server.credentials[reference] || "external";
      const ref = element("p", "Credential reference " + reference + ": ", "help");
      pill(ref, status, status === "set");
      box.append(ref);
      if (!(reference in server.credentials)) continue;
      const input = secretInput(box, "New value for " + reference);
      const refRow = actions(box);
      button(refRow, "Save credential", async () => {
        const value = input.value;
        input.value = "";
        await run("credential-set", server.id, {reference, value});
        showNotice("Credential saved in the OS store.");
      }, true);
      button(refRow, "Remove credential", async () => {
        await run("credential-delete", server.id, {reference});
        showNotice("Credential removed.");
      }, true);
    }
    const details = element("details");
    details.append(element("summary", "Edit or remove"));
    box.append(details);
    const profile = profileFields(details, server.profile);
    const editRow = actions(details);
    button(editRow, "Save profile", async () => {
      await run("edit", server.id, {profile: JSON.parse(profile.value), revision: data.revision});
      await reload();
      showNotice("Saved and verified. Restart the affected services to apply runtime changes.");
    });
    button(editRow, "Remove connection", async () => {
      if (!confirm("Remove connection " + server.id + "?")) return;
      await run("remove", server.id, {revision: data.revision});
      await reload();
      showNotice("Connection removed.");
    }, true);
  }
  const add = card("Add a connection");
  const name = textInput(add, "Connection name");
  const profile = profileFields(add, null);
  button(add, "Add connection", async () => {
    await run("add", name.value.trim(), {profile: JSON.parse(profile.value), revision: data.revision});
    await reload();
    showNotice("Connection added. It has no authorized tools until you add them to the policy.");
  });
  if (!snapshot) await reload();
  editor("Tool and web policy", "bridge_config.json", snapshot.sections.Connections, "Connections");
  const box = card("Executable extension policy");
  box.append(element("p", "This control becomes available when issue #25 supplies the shared platform-policy API.", "help"));
}

async function renderServices() {
  const data = await api("services");
  const pm2 = card("Services");
  if (!data.pm2.available) {
    pm2.append(element("p", "PM2 status is unavailable in this folder. Install checkout-local PM2 and Node from the Setup checklist.", "help"));
  } else {
    pm2.append(element("p", data.pm2.daemon ? "PM2 daemon running for this checkout." : "PM2 daemon is not running. Start all services to launch it.", "help"));
  }
  const console = checkbox(pm2, "Start with troubleshooting console windows");
  const rows = Object.fromEntries((data.pm2.services || []).map(row => [row.name, row]));
  const table = element("ul", "", "steps");
  for (const name of data.names) {
    const row = element("li");
    row.append(element("span", name, "step"));
    const current = rows[name];
    pill(row, current ? current.status : "not listed", current ? current.status === "online" : null);
    if (current) row.append(element("span", "restarts " + current.restarts, "help"));
    for (const action of ["start", "stop", "restart"]) {
      button(row, action[0].toUpperCase() + action.slice(1), async () => {
        if (action !== "start" && !confirm(action + " " + name + "?")) return;
        await api("services", {action, name, console: action === "start" && console.checked});
        await render("Services");
        showNotice(name + ": " + action + " sent.");
      }, true);
    }
    table.append(row);
  }
  pm2.append(table);
  button(pm2, "Start all services", async () => {
    showNotice("Running preflight and starting services…");
    await api("services", {action: "start-all", console: console.checked});
    await render("Services");
    showNotice("Started. Inspect health and logs before saving the PM2 roster.");
  });
  const health = card("Health");
  const current = data.health.current;
  const line = element("p", "", "help");
  line.append("Current: ");
  pill(line, current.status, current.status === "ok" ? true : current.status === "unavailable" ? null : false);
  line.append(" · monitor snapshot " + since(data.health.monitor_age_seconds));
  health.append(line);
  for (const bot of current.bots) {
    const row = element("p", "Bot " + bot.bot_id + ": heartbeat " + since(bot.age_seconds) + " ", "help");
    pill(row, bot.stale ? "stale" : bot.ready ? "ready" : "not ready", bot.ready && !bot.stale);
    health.append(row);
  }
  if (current.failures.length) health.append(element("div", current.failures.join("\n"), "result"));
  const recovery = card("Recovery");
  const r = data.health.recovery;
  const rline = element("p", "", "help");
  rline.append("Last recovery report: ");
  pill(rline, r.state ? r.state.status : "none", r.state ? r.state.status === "ok" : null);
  rline.append(" · " + since(r.state_age_seconds) + (r.maintenance ? " · maintenance mode on" : ""));
  recovery.append(rline);
  button(recovery, r.maintenance ? "Turn maintenance mode off" : "Turn maintenance mode on", async () => {
    await api("services", {action: "maintenance", enabled: !r.maintenance});
    await render("Services");
    showNotice(r.maintenance ? "Recovery resumed." : "Recovery paused for maintenance.");
  }, true);
  const task = textInput(recovery, "Recovery task name (use a distinct name per installation)", "BotBridge-Recovery");
  const trow = actions(recovery);
  button(trow, "Check task", async () => {
    const result = await api("services", {action: "task-status", task: task.value});
    showNotice("Task " + result.task + ": " + (result.installed === null ? "unknown" : result.installed ? "installed" : "not installed") + ".");
  }, true);
  button(trow, "Install task", async () => {
    if (!confirm("Register the hidden recovery task " + task.value + " for this checkout?")) return;
    await api("services", {action: "task-install", task: task.value});
    showNotice("Recovery task installed.");
  }, true);
  button(trow, "Remove task", async () => {
    if (!confirm("Remove the recovery task " + task.value + "?")) return;
    await api("services", {action: "task-remove", task: task.value});
    showNotice("Recovery task removed.");
  }, true);
  const logs = card("Logs");
  const pick = element("select");
  for (const name of [...data.names, "health", "recovery"]) {
    const option = element("option", name);
    option.value = name;
    pick.append(option);
  }
  logs.append(pick);
  const output = element("div", "", "result log");
  button(logs, "Show recent lines", async () => {
    const result = await api("logs?name=" + encodeURIComponent(pick.value));
    output.textContent = result.text === null ? "No log file yet." : result.text;
  }, true);
  logs.append(output);
}

async function renderDiagnostics() {
  const pre = card("Preflight");
  pre.append(element("p", "Runs the same read-only preflight as the CLI. It does not start bots or post messages.", "help"));
  button(pre, "Run preflight", async () => {
    const result = await api("checklist", {action: "preflight"});
    showNotice("Preflight " + result.preflight + ".", result.preflight !== "passed");
  });
  const checks = card("Provider checks");
  checks.append(element("p", "Checks sign-in and credentials without generating replies or using credits.", "help"));
  const row = actions(checks);
  for (const role of ["codex", "claude"]) {
    button(row, ROLE_LABEL[role] + " sign-in", async () => {
      const result = await api("providers", {action: "login", target: role});
      showNotice(ROLE_LABEL[role] + ": " + result.login.replaceAll("_", " ") + ".", result.login !== "signed_in");
    }, true);
  }
  for (const name of ["GEMINI_API_KEY", ...Object.values(ROLE_TOKEN)]) {
    button(row, "Verify " + CREDENTIAL_LABELS[name], async () => {
      const result = await api("providers", {action: "verify", target: name});
      showNotice(CREDENTIAL_LABELS[name] + ": " + result.check.replaceAll("_", " ") + ".", result.check !== "passed");
    }, true);
  }
  const message = card("Test message (optional)");
  message.append(element("p", "Posts one fixed message to the configured channel through Discord's REST API. It opens no second gateway connection.", "help"));
  const pick = element("select");
  for (const role of Object.keys(ROLE_TOKEN)) {
    const option = element("option", ROLE_LABEL[role]);
    option.value = role;
    pick.append(option);
  }
  message.append(pick);
  const confirmed = checkbox(message, "Send a visible test message to the configured channel");
  button(message, "Send test message", async () => {
    const result = await api("providers", {action: "message", target: pick.value, confirm: confirmed.checked});
    confirmed.checked = false;
    showNotice(result.sent ? "Test message sent." : "Discord refused the test message.", !result.sent);
  });
}

async function renderBackup() {
  const out = card("Export settings");
  out.append(element("p", "Downloads bridge_config.json, local_settings.json and public_context.md as one file. Credentials stay in the OS store or environment.", "help"));
  button(out, "Download export", async () => {
    const response = await fetch("/api/export", {headers: {Authorization: "Bearer " + token}, cache: "no-store"});
    if (!response.ok) throw new Error("Export refused. Reload and try again.");
    // Kept as text: parsing would round Discord IDs.
    const link = element("a");
    link.href = URL.createObjectURL(new Blob([await response.text()], {type: "application/json"}));
    link.download = "botbridge-settings.json";
    link.click();
    URL.revokeObjectURL(link.href);
    showNotice("Export downloaded.");
  });
  const box = card("Import settings");
  box.append(element("p", "The whole export is validated with the runtime policy before any file changes. All three files are replaced together, or none.", "help"));
  const file = element("input");
  file.type = "file";
  file.accept = "application/json,.json";
  box.append(file);
  const risk = checkbox(box, "I authorize owner work if the imported settings enable it.");
  button(box, "Import", async () => {
    if (!file.files.length) throw new Error("Choose an export file first.");
    const bundle = await file.files[0].text();
    await api("import", {bundle, revisions: snapshot.revisions, confirm_work: risk.checked});
    file.value = "";
    await reload();
    showNotice("Imported and verified. Restart the affected services to apply runtime changes.");
  });
}

async function render(section) {
  document.querySelector("#title").textContent = section;
  document.querySelector("#description").textContent = sections[section];
  for (const node of document.querySelectorAll("nav button")) {
    node.setAttribute("aria-current", node.textContent === section ? "page" : "false");
  }
  content.replaceChildren();
  showNotice("");
  if (section === "Setup") return renderSetup();
  if (!snapshot) await reload();
  if (section === "Credentials") return renderCredentials();
  if (section === "Providers") return renderProviders();
  if (section === "Connections") return renderConnections();
  if (section === "Services") return renderServices();
  if (section === "Diagnostics") return renderDiagnostics();
  if (section === "Backup") return renderBackup();
  if (section in snapshot.forms) return typedEditor(section);
  if (section === "Privacy") {
    editor("Public context", "public_context.md", snapshot.context);
    editor("Local paths", "local_settings.json", snapshot.settings);
    const box = card("Redaction preview");
    const input = textInput(box, "Sample text", "", true);
    const result = element("div", "", "result");
    result.setAttribute("aria-live", "polite");
    button(box, "Preview redaction", async () => {
      const data = await api("redact", {text: input.value});
      result.textContent = data.text;
    });
    box.append(result);
    return;
  }
  editor(section + " settings", "bridge_config.json", snapshot.sections[section], section);
}

for (const section of Object.keys(sections)) {
  button(document.querySelector("nav"), section, () => render(section));
}
render("Setup").catch(error => showNotice(error.message, true));
