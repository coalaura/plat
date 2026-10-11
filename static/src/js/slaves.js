const refreshInterval = 5000;

export function createSlavesPanel(api) {
	const panel = element("section", "panel slaves"),
		header = element("div", "panel-head"),
		title = element("h2", "panel-title", "Slaves"),
		refresh = element("button", "ghost", "Refresh"),
		summary = element("p", "panel-subtitle", "Replication health across all trusted slaves."),
		feedback = element("p", "slaves-feedback"),
		content = element("div", "slaves-content"),
		updated = element("p", "note", "Refreshes every 5 seconds while this tab is visible.");

	let active = false,
		destroyed = false,
		timer = null,
		controller = null,
		lastUpdated = null;

	refresh.type = "button";

	feedback.hidden = true;
	feedback.setAttribute("role", "status");

	header.append(title, refresh);
	panel.append(header, summary, feedback, content, updated);

	function stop() {
		window.clearTimeout(timer);
		timer = null;

		controller?.abort();
		controller = null;

		refresh.disabled = false;
		refresh.textContent = "Refresh";

		content.setAttribute("aria-busy", "false");
	}

	async function load() {
		if (!active || destroyed || document.hidden || controller) {
			return;
		}

		window.clearTimeout(timer);

		const current = new AbortController();

		controller = current;

		refresh.disabled = true;
		refresh.textContent = "Refreshing...";

		content.setAttribute("aria-busy", "true");

		if (!lastUpdated) {
			content.replaceChildren(element("p", "empty", "Loading slaves..."));
		}

		try {
			const data = await api("/-/slaves", { signal: current.signal, cache: "no-store" });

			if (controller !== current) {
				return;
			}

			const scrollTop = content.scrollTop,
				scrollLeft = content.scrollLeft;

			renderSlaves(data, summary, content);

			content.scrollTop = scrollTop;
			content.scrollLeft = scrollLeft;

			lastUpdated = new Date();

			feedback.hidden = true;

			updated.textContent = `Updated ${lastUpdated.toLocaleTimeString()}. Refreshes every 5 seconds while this tab is visible.`;
		} catch (error) {
			if (controller !== current) {
				return;
			}

			feedback.textContent = `Could not refresh slave status: ${error.message}${lastUpdated ? " Displayed status may be outdated." : ""}`;
			feedback.hidden = false;

			if (!lastUpdated) {
				content.replaceChildren();
			}
		} finally {
			if (controller === current) {
				controller = null;

				refresh.disabled = false;
				refresh.textContent = "Refresh";

				content.setAttribute("aria-busy", "false");

				timer = window.setTimeout(load, refreshInterval);
			}
		}
	}

	function onVisibilityChange() {
		if (document.hidden) {
			stop();
		} else {
			load();
		}
	}

	refresh.addEventListener("click", load);

	document.addEventListener("visibilitychange", onVisibilityChange);

	return {
		element: panel,
		setActive(value) {
			if (active === value || destroyed) {
				return;
			}

			active = value;

			if (active) {
				load();
			} else {
				stop();
			}
		},
		destroy() {
			destroyed = true;

			stop();

			document.removeEventListener("visibilitychange", onVisibilityChange);
		},
	};
}

function renderSlaves(data, summary, content) {
	if (!data || typeof data.enabled !== "boolean") {
		throw new Error("Invalid slave status response.");
	}

	if (!data.enabled) {
		summary.textContent = "Replication is disabled.";

		content.replaceChildren(element("p", "empty", "Set cluster.enabled to true in config.yml and restart the master to enable replication."));

		return;
	}

	const slaves = Object.entries(data.slaves || {}).sort(([leftID, left], [rightID, right]) => {
		return left.name.localeCompare(right.name) || leftID.localeCompare(rightID);
	});

	let connected = 0,
		upToDate = 0;

	const table = element("table", "record-table slaves-table"),
		head = element("thead"),
		headRow = element("tr"),
		body = element("tbody");

	for (const label of ["Slave", "Status", "Applied revision", "Last seen", "Last applied"]) {
		const cell = element("th", "", label);

		cell.scope = "col";

		headRow.append(cell);
	}

	for (const [id, slave] of slaves) {
		const current = slave.connected && slave.ready && slave.epoch === data.epoch && slave.sequence === data.sequence,
			row = element("tr"),
			identity = cell("Slave"),
			health = cell("Status"),
			progress = cell("Applied revision");

		let status = slave.last_receive || slave.error ? "Offline" : "Not connected",
			tone = "offline";

		if (slave.connected) {
			status = current ? "Up to date" : "Syncing";
			tone = current ? "healthy" : "syncing";
		}

		connected += Number(slave.connected);
		upToDate += Number(current);

		identity.append(element("strong", "slave-name", slave.name || id), element("code", "slave-fingerprint mono", id));
		health.append(element("span", `slave-status ${tone}`, status));

		if (slave.error) {
			health.append(element("p", "slave-error", slave.error));
		}

		if (slave.last_applied) {
			progress.append(element("span", "mono", slave.sequence), element("code", "slave-epoch mono", slave.epoch));
		} else {
			progress.textContent = "Not yet applied";
		}

		row.append(identity, health, progress, timeCell("Last seen", slave.last_receive), timeCell("Last applied", slave.last_applied));
		body.append(row);
	}

	summary.textContent = `${slaves.length} trusted · ${connected} connected · ${upToDate} up to date`;
	summary.title = `Master epoch: ${data.epoch}; revision: ${data.sequence}`;

	head.append(headRow);
	table.append(head, body);

	if (slaves.length) {
		content.replaceChildren(table);
	} else {
		content.replaceChildren(element("p", "empty", "No trusted slaves. Copy each slave's public certificate into cluster.trusted_clients (data/certs/slaves by default), then restart the master."));
	}
}

function timeCell(label, value) {
	const result = cell(label);

	if (!value) {
		result.textContent = "Never";

		return result;
	}

	const time = element("time", "", new Date(value).toLocaleString());

	time.dateTime = value;
	time.title = value;

	result.append(time);

	return result;
}

function cell(label) {
	const result = element("td");

	result.dataset.label = label;

	return result;
}

function element(tag, classes = "", text = "") {
	const result = document.createElement(tag);

	result.className = classes;
	result.textContent = text;

	return result;
}
