const output = document.querySelector("#terminal-output");
const input = document.querySelector("#command-input");
const form = document.querySelector("#command-form");
const eventsBody = document.querySelector("#events-body");

function addOutput(command, response, techniques) {
  const commandLine = document.createElement("div");
  commandLine.className = "command-line";
  const prompt = document.createElement("span");
  prompt.className = "terminal-prompt";
  prompt.textContent = `analyst@decoy:${document.querySelector("#cwd").textContent}$ `;
  commandLine.append(prompt, document.createTextNode(command));
  output.append(commandLine);

  const responseLine = document.createElement("div");
  responseLine.className = "response-line";
  responseLine.textContent = response || "(no output)";
  output.append(responseLine);
  if (techniques.length) {
    const note = document.createElement("div");
    note.className = "technique-note";
    note.textContent = `ATT&CK observed: ${techniques.join(", ")}`;
    output.append(note);
  }
  output.scrollTop = output.scrollHeight;
}

function makeCell(className, text) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text;
  return cell;
}

function renderEvents(events) {
  eventsBody.replaceChildren();
  if (!events.length) {
    const row = document.createElement("tr");
    row.className = "empty-row";
    const cell = makeCell("", "No activity yet. Try a command in the simulated shell.");
    cell.colSpan = 4;
    row.append(cell);
    eventsBody.append(row);
  }

  const uniqueTechniques = new Set();
  const uniqueIndicators = new Set();
  for (const event of events) {
    const row = document.createElement("tr");
    const date = new Date(event.created_at);
    row.append(makeCell("time-cell", date.toLocaleTimeString()));
    row.append(makeCell("command-cell", event.command));

    const techniqueCell = document.createElement("td");
    const tagList = document.createElement("div");
    tagList.className = "tag-list";
    for (const technique of event.techniques) {
      uniqueTechniques.add(technique);
      const tag = document.createElement("span");
      tag.className = "tag";
      tag.textContent = technique;
      tagList.append(tag);
    }
    techniqueCell.append(tagList);
    row.append(techniqueCell);

    const indicatorCell = document.createElement("td");
    for (const indicator of event.indicators) {
      const key = `${indicator.kind}:${indicator.value}`;
      uniqueIndicators.add(key);
      const value = document.createElement("div");
      value.className = "indicator";
      value.textContent = indicator.value;
      indicatorCell.append(value);
    }
    row.append(indicatorCell);
    eventsBody.append(row);
  }

  document.querySelector("#command-count").textContent = String(events.length);
  document.querySelector("#technique-count").textContent = String(uniqueTechniques.size);
  document.querySelector("#indicator-count").textContent = String(uniqueIndicators.size);
  document.querySelector("#event-count").textContent = `${events.length} EVENTS`;
}

async function refreshEvents() {
  const response = await fetch("/api/events");
  if (!response.ok) throw new Error(`Could not load events (${response.status}).`);
  const data = await response.json();
  renderEvents(data.events);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const command = input.value.trim();
  if (!command) return;
  input.value = "";
  try {
    const response = await fetch("/api/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Command request failed.");
    document.querySelector("#cwd").textContent = data.cwd;
    addOutput(command, data.response, data.techniques);
    await refreshEvents();
  } catch (error) {
    addOutput(command, `Request error: ${error.message}`, []);
  }
  input.focus();
});

document.querySelectorAll("[data-command]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.command;
    form.requestSubmit();
  });
});

document.querySelector("#refresh-button").addEventListener("click", () => {
  refreshEvents().catch((error) => window.alert(error.message));
});

document.querySelector("#export-button").addEventListener("click", () => {
  window.location.assign("/api/stix");
});

refreshEvents().catch((error) => window.alert(error.message));
