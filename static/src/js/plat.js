import "../css/plat.css";

const app = document.getElementById("app");

const TOKEN_KEY = "plat-token";
const ROOT_LABEL = "@";

const RECORD_TYPES = [
	"A",
	"AAAA",
	"CAA",
	"CERT",
	"CNAME",
	"DNSKEY",
	"DS",
	"HTTPS",
	"LOC",
	"MX",
	"NAPTR",
	"NS",
	"OPENPGPKEY",
	"PTR",
	"SMIMEA",
	"SRV",
	"SSHFP",
	"SVCB",
	"TLSA",
	"TXT",
	"URI",
];

let state = {
	token: sessionStorage.getItem(TOKEN_KEY) || "",
	authenticated: false,
	zones: [],
	activeZone: "",
	records: [],
	loading: false,
	message: "",
	error: "",
};

function make(tag, ...classes) {
	classes = classes.filter(Boolean);

	const el = document.createElement(tag);

	if (classes.length) {
		el.classList.add(...classes);
	}

	return el;
}

function recordTypeConfig(type) {
	const map = {
		A: {
			description: "IPv4 address.",
			fields: [{ key: "address", label: "IPv4", placeholder: "203.0.113.5", required: true, hint: "A single IPv4 address." }],
			build: (data) => data.address,
		},
		AAAA: {
			description: "IPv6 address.",
			fields: [{ key: "address", label: "IPv6", placeholder: "2001:db8::5", required: true, hint: "A single IPv6 address." }],
			build: (data) => data.address,
		},
		CNAME: {
			description: "Alias to another hostname.",
			fields: [{ key: "target", label: "Target", placeholder: "service.example.net.", required: true, hint: "Canonical target hostname." }],
			build: (data) => data.target,
		},
		NS: {
			description: "Delegated authoritative nameserver.",
			fields: [{ key: "host", label: "Nameserver", placeholder: "ns1.example.net.", required: true, hint: "Nameserver hostname." }],
			build: (data) => data.host,
		},
		PTR: {
			description: "Reverse DNS pointer target.",
			fields: [{ key: "target", label: "Target", placeholder: "host.example.com.", required: true, hint: "Hostname returned by reverse lookup." }],
			build: (data) => data.target,
		},
		TXT: {
			description: "Arbitrary text payload.",
			fields: [{ key: "text", label: "Text", placeholder: "v=spf1 include:_spf.example.com ~all", required: true, hint: "Use raw text value." }],
			build: (data) => data.text,
		},
		MX: {
			description: "Mail exchanger with priority.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "exchange", label: "Exchange", placeholder: "mail.example.com.", required: true, hint: "Mail server hostname." },
			],
			build: (data) => `${data.priority} ${data.exchange}`,
		},
		CAA: {
			description: "Certificate Authority Authorization policy.",
			fields: [
				{ key: "flags", label: "Flags", placeholder: "0", required: true, hint: "0 for normal, 128 for critical." },
				{ key: "tag", label: "Tag", placeholder: "issue", required: true, hint: "issue, issuewild, or iodef." },
				{ key: "value", label: "Value", placeholder: "letsencrypt.org", required: true, hint: "CA domain or reporting URL." },
			],
			build: (data) => `${data.flags} ${data.tag} ${quote(data.value)}`,
		},
		SRV: {
			description: "Service location details.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values first." },
				{ key: "weight", label: "Weight", placeholder: "5", required: true, hint: "Relative balancing weight." },
				{ key: "port", label: "Port", placeholder: "443", required: true, hint: "Destination service port." },
				{ key: "target", label: "Target", placeholder: "service.example.com.", required: true, hint: "Destination hostname." },
			],
			build: (data) => `${data.priority} ${data.weight} ${data.port} ${data.target}`,
		},
		URI: {
			description: "Service URI with priority and weight.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "weight", label: "Weight", placeholder: "1", required: true, hint: "Relative balancing weight." },
				{ key: "target", label: "Target URI", placeholder: "https://example.com/api", required: true, hint: "Quoted URI target." },
			],
			build: (data) => `${data.priority} ${data.weight} ${quote(data.target)}`,
		},
		TLSA: {
			description: "TLS certificate association data.",
			fields: [
				{ key: "usage", label: "Usage", placeholder: "3", required: true, hint: "Certificate usage selector." },
				{ key: "selector", label: "Selector", placeholder: "1", required: true, hint: "0 full cert, 1 subject public key." },
				{ key: "matching", label: "Matching Type", placeholder: "1", required: true, hint: "0 full, 1 SHA-256, 2 SHA-512." },
				{ key: "data", label: "Certificate Data", placeholder: "aabbcc...", required: true, hint: "Hex encoded association data." },
			],
			build: (data) => `${data.usage} ${data.selector} ${data.matching} ${data.data}`,
		},
		SSHFP: {
			description: "SSH fingerprint metadata.",
			fields: [
				{ key: "algorithm", label: "Algorithm", placeholder: "4", required: true, hint: "1 RSA, 2 DSA, 3 ECDSA, 4 Ed25519." },
				{ key: "fpType", label: "Fingerprint Type", placeholder: "2", required: true, hint: "1 SHA-1 or 2 SHA-256." },
				{ key: "fingerprint", label: "Fingerprint", placeholder: "ab12...", required: true, hint: "Hex encoded fingerprint." },
			],
			build: (data) => `${data.algorithm} ${data.fpType} ${data.fingerprint}`,
		},
		DNSKEY: {
			description: "DNSSEC public key material.",
			fields: [
				{ key: "flags", label: "Flags", placeholder: "257", required: true, hint: "Commonly 256 (ZSK) or 257 (KSK)." },
				{ key: "protocol", label: "Protocol", placeholder: "3", required: true, hint: "Must be 3 for DNSSEC." },
				{ key: "algorithm", label: "Algorithm", placeholder: "13", required: true, hint: "DNSSEC signing algorithm." },
				{ key: "publicKey", label: "Public Key", placeholder: "AwEAA...", required: true, hint: "Base64 public key data." },
			],
			build: (data) => `${data.flags} ${data.protocol} ${data.algorithm} ${data.publicKey}`,
		},
		DS: {
			description: "Delegation Signer digest.",
			fields: [
				{ key: "keyTag", label: "Key Tag", placeholder: "2371", required: true, hint: "Key identifier." },
				{ key: "algorithm", label: "Algorithm", placeholder: "13", required: true, hint: "DNSSEC algorithm number." },
				{ key: "digestType", label: "Digest Type", placeholder: "2", required: true, hint: "1 SHA-1, 2 SHA-256, 4 SHA-384." },
				{ key: "digest", label: "Digest", placeholder: "ab12...", required: true, hint: "Hex digest string." },
			],
			build: (data) => `${data.keyTag} ${data.algorithm} ${data.digestType} ${data.digest}`,
		},
		NAPTR: {
			description: "Regex-based rewrite rules.",
			fields: [
				{ key: "order", label: "Order", placeholder: "100", required: true, hint: "Lower values first." },
				{ key: "preference", label: "Preference", placeholder: "10", required: true, hint: "Lower values preferred inside same order." },
				{ key: "flags", label: "Flags", placeholder: "s", required: true, hint: "Control interpretation." },
				{ key: "service", label: "Service", placeholder: "SIP+D2U", required: true, hint: "Service parameters." },
				{ key: "regexp", label: "Regexp", placeholder: "", required: false, hint: "Optional regex rewrite." },
				{ key: "replacement", label: "Replacement", placeholder: "_sip._udp.example.com.", required: true, hint: "Target replacement domain." },
			],
			build: (data) => `${data.order} ${data.preference} ${quote(data.flags)} ${quote(data.service)} ${quote(data.regexp || "")} ${data.replacement}`,
		},
		CERT: {
			description: "Certificate record payload.",
			fields: [
				{ key: "certType", label: "Certificate Type", placeholder: "1", required: true, hint: "Numeric certificate type code." },
				{ key: "keyTag", label: "Key Tag", placeholder: "0", required: true, hint: "Associated key tag." },
				{ key: "algorithm", label: "Algorithm", placeholder: "0", required: true, hint: "Algorithm identifier." },
				{ key: "certificate", label: "Certificate", placeholder: "MIIB...", required: true, hint: "Base64 certificate data." },
			],
			build: (data) => `${data.certType} ${data.keyTag} ${data.algorithm} ${data.certificate}`,
		},
		OPENPGPKEY: {
			description: "OpenPGP public key packet.",
			fields: [{ key: "packet", label: "Public Key Packet", placeholder: "mQENBF...", required: true, hint: "Base64 encoded packet body." }],
			build: (data) => data.packet,
		},
		SMIMEA: {
			description: "S/MIME certificate association.",
			fields: [
				{ key: "usage", label: "Usage", placeholder: "3", required: true, hint: "Certificate usage." },
				{ key: "selector", label: "Selector", placeholder: "1", required: true, hint: "Selector code." },
				{ key: "matching", label: "Matching Type", placeholder: "1", required: true, hint: "Digest or full match selector." },
				{ key: "data", label: "Certificate Data", placeholder: "aabb...", required: true, hint: "Hex association data." },
			],
			build: (data) => `${data.usage} ${data.selector} ${data.matching} ${data.data}`,
		},
		LOC: {
			description: "Geographic location.",
			fields: [
				{ key: "lat", label: "Latitude", placeholder: "37 47 0.000 N", required: true, hint: "Latitude in LOC format." },
				{ key: "lng", label: "Longitude", placeholder: "122 24 0.000 W", required: true, hint: "Longitude in LOC format." },
				{ key: "alt", label: "Altitude", placeholder: "10m", required: true, hint: "Altitude, defaults often in meters." },
				{ key: "size", label: "Size", placeholder: "1m", required: false, hint: "Optional sphere size." },
				{ key: "hPrec", label: "Horiz Precision", placeholder: "10000m", required: false, hint: "Optional horizontal precision." },
				{ key: "vPrec", label: "Vert Precision", placeholder: "10m", required: false, hint: "Optional vertical precision." },
			],
			build: (data) => [data.lat, data.lng, data.alt, data.size, data.hPrec, data.vPrec].filter(Boolean).join(" "),
		},
		HTTPS: {
			description: "HTTPS service binding (SVCB alias mode or service mode).",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: ".", required: true, hint: "Target name, usually . or a hostname." },
				{ key: "params", label: "Svc Params", placeholder: "alpn=\"h3,h2\" ipv4hint=203.0.113.5", required: false, hint: "Space-separated key=value parameters." },
			],
			build: (data) => [data.priority, data.target, data.params].filter(Boolean).join(" "),
		},
		SVCB: {
			description: "Generic service binding record.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: "svc.example.com.", required: true, hint: "Service target name." },
				{ key: "params", label: "Svc Params", placeholder: "alpn=\"h2\" port=443", required: false, hint: "Space-separated key=value parameters." },
			],
			build: (data) => [data.priority, data.target, data.params].filter(Boolean).join(" "),
		},
	};

	return map[type] || {
		description: "Raw record value.",
		fields: [{ key: "value", label: "Value", placeholder: "", required: true, hint: "Raw record value." }],
		build: (data) => data.value,
	};
}

function quote(value) {
	if (!value) {
		return "\"\"";
	}

	const clean = String(value).trim().replace(/\"/g, '\\"');

	if (clean.startsWith("\"") && clean.endsWith("\"")) {
		return clean;
	}

	return `"${clean}"`;
}

function normalizeZone(zone) {
	return zone.endsWith(".") ? zone : `${zone}.`;
}

function zoneDisplay(zone) {
	return zone.endsWith(".") ? zone.slice(0, -1) : zone;
}

function setStatus(message, isError) {
	state.message = isError ? "" : message;
	state.error = isError ? message : "";
	render();
}

async function api(path, options = {}) {
	const headers = options.headers ? { ...options.headers } : {};

	if (state.token) {
		headers.Authorization = `Bearer ${state.token}`;
	}

	if (options.body && !headers["Content-Type"]) {
		headers["Content-Type"] = "application/json";
	}

	const response = await fetch(path, {
		...options,
		headers,
	});

	const text = await response.text();
	let payload = null;

	if (text) {
		try {
			payload = JSON.parse(text);
		} catch {
			payload = null;
		}
	}

	if (!response.ok) {
		throw new Error(payload?.error || `Request failed (${response.status})`);
	}

	return payload;
}

async function checkInfo() {
	const info = await api("/-/info");

	state.authenticated = Boolean(info?.authenticated);
	state.zones = Array.isArray(info?.zones) ? info.zones : [];

	if (!state.authenticated) {
		state.activeZone = "";
		state.records = [];
		return;
	}

	if (!state.zones.length) {
		state.activeZone = "";
		state.records = [];
		return;
	}

	if (!state.activeZone || !state.zones.includes(state.activeZone)) {
		state.activeZone = state.zones[0];
	}

	await loadZone(state.activeZone);
}

async function loadZone(zone) {
	if (!zone) {
		state.records = [];
		return;
	}

	state.loading = true;
	render();

	try {
		const records = await api(`/-/${encodeURIComponent(normalizeZone(zone))}`);
		state.records = Array.isArray(records) ? records : [];
		state.activeZone = zone;
		state.message = "";
		state.error = "";
	} catch (err) {
		state.records = [];
		state.error = err.message;
	} finally {
		state.loading = false;
		render();
	}
}

async function refreshZoneFromCloudflare() {
	if (!state.activeZone) {
		return;
	}

	state.loading = true;
	render();

	try {
		const records = await api(`/-/${encodeURIComponent(normalizeZone(state.activeZone))}`, {
			method: "PATCH",
		});

		state.records = Array.isArray(records) ? records : [];
		setStatus("Zone refreshed from Cloudflare.", false);
	} catch (err) {
		setStatus(err.message, true);
	} finally {
		state.loading = false;
		render();
	}
}

async function saveRecord(record, isUpdate) {
	await api(`/-/${encodeURIComponent(normalizeZone(state.activeZone))}`, {
		method: isUpdate ? "PUT" : "POST",
		body: JSON.stringify(record),
	});

	setStatus(isUpdate ? "Record updated." : "Record created.", false);
	await loadZone(state.activeZone);
}

async function deleteRecord(recordName) {
	await api(`/-/${encodeURIComponent(normalizeZone(state.activeZone))}/${encodeURIComponent(recordName)}`, {
		method: "DELETE",
	});

	setStatus(`Deleted ${recordName}.`, false);
	await loadZone(state.activeZone);
}

function parseFormRecord(formData) {
	const mode = formData.get("mode");
	const type = String(formData.get("type") || "A").toUpperCase();
	const name = String(formData.get("name") || "").trim();
	const ttl = Number.parseInt(String(formData.get("ttl") || "1"), 10);

	if (!name) {
		throw new Error("Record name is required.");
	}

	if (!Number.isFinite(ttl) || ttl < 1) {
		throw new Error("TTL must be a positive number.");
	}

	let value = "";

	if (mode === "raw") {
		value = String(formData.get("rawValue") || "").trim();
	} else {
		const config = recordTypeConfig(type);
		const fieldData = {};

		for (const field of config.fields) {
			const key = `field_${field.key}`;
			const current = String(formData.get(key) || "").trim();
			if (field.required && !current) {
				throw new Error(`${field.label} is required for ${type}.`);
			}
			fieldData[field.key] = current;
		}

		value = config.build(fieldData).trim();
	}

	if (!value) {
		throw new Error("Record value cannot be empty.");
	}

	return {
		type,
		name,
		value,
		ttl,
	};
}

function makeField(field, current) {
	const wrap = make("label", "field");
	const title = make("span", "field-title");
	const hint = make("span", "field-hint");
	const input = make("input", "input");

	title.textContent = field.label;
	hint.textContent = field.hint || "";

	input.type = "text";
	input.name = `field_${field.key}`;
	input.placeholder = field.placeholder || "";
	input.value = current?.[field.key] || "";

	wrap.append(title, input, hint);

	return wrap;
}

function openRecordModal(currentRecord) {
	const overlay = make("div", "overlay");
	const modal = make("div", "modal");
	const top = make("div", "modal-top");
	const title = make("h2", "modal-title");
	const closeButton = make("button", "ghost");
	const form = make("form", "record-form");
	const modeRow = make("div", "inline-row");
	const modeLabel = make("span", "field-title");
	const modeSelect = make("select", "input");
	const rawWrap = make("label", "field");
	const rawTitle = make("span", "field-title");
	const rawHint = make("span", "field-hint");
	const rawInput = make("textarea", "input", "textarea");
	const dynamicSection = make("div", "dynamic-fields");
	const footer = make("div", "modal-foot");
	const submitButton = make("button", "button");
	const cancelButton = make("button", "ghost");

	const modeDefault = currentRecord ? "raw" : "typed";

	title.textContent = currentRecord ? "Edit record" : "Create record";
	closeButton.type = "button";
	closeButton.textContent = "Close";
	modeLabel.textContent = "Input mode";

	const modeTyped = make("option");
	const modeRaw = make("option");
	modeTyped.value = "typed";
	modeTyped.textContent = "Typed fields";
	modeRaw.value = "raw";
	modeRaw.textContent = "Raw value";
	modeSelect.name = "mode";
	modeSelect.append(modeTyped, modeRaw);
	modeSelect.value = modeDefault;

	rawTitle.textContent = "Raw value";
	rawHint.textContent = "Direct record value string sent to backend.";
	rawInput.name = "rawValue";
	rawInput.rows = 4;
	rawInput.value = currentRecord?.value || "";

	const nameField = make("label", "field");
	const nameTitle = make("span", "field-title");
	const nameHint = make("span", "field-hint");
	const nameInput = make("input", "input");
	nameTitle.textContent = "Name";
	nameHint.textContent = "Use @ for zone root.";
	nameInput.type = "text";
	nameInput.name = "name";
	nameInput.placeholder = ROOT_LABEL;
	nameInput.value = currentRecord?.name || ROOT_LABEL;
	nameField.append(nameTitle, nameInput, nameHint);

	const typeField = make("label", "field");
	const typeTitle = make("span", "field-title");
	const typeHint = make("span", "field-hint");
	const typeInput = make("select", "input");
	typeTitle.textContent = "Type";
	typeHint.textContent = "All Cloudflare DNS record types are available.";
	typeInput.name = "type";
	for (const type of RECORD_TYPES) {
		const option = make("option");
		option.value = type;
		option.textContent = type;
		typeInput.append(option);
	}
	typeInput.value = currentRecord?.type || "A";
	typeField.append(typeTitle, typeInput, typeHint);

	const ttlField = make("label", "field");
	const ttlTitle = make("span", "field-title");
	const ttlHint = make("span", "field-hint");
	const ttlInput = make("input", "input");
	ttlTitle.textContent = "TTL (seconds)";
	ttlHint.textContent = "Stored as integer seconds.";
	ttlInput.type = "number";
	ttlInput.min = "1";
	ttlInput.step = "1";
	ttlInput.name = "ttl";
	ttlInput.value = String(currentRecord?.ttl || 1);
	ttlField.append(ttlTitle, ttlInput, ttlHint);

	const typedDescription = make("p", "typed-description");

	submitButton.type = "submit";
	submitButton.textContent = currentRecord ? "Save" : "Create";
	cancelButton.type = "button";
	cancelButton.textContent = "Cancel";

	modeRow.append(modeLabel, modeSelect);
	rawWrap.append(rawTitle, rawInput, rawHint);
	footer.append(submitButton, cancelButton);
	top.append(title, closeButton);
	form.append(top, nameField, typeField, ttlField, modeRow, typedDescription, dynamicSection, rawWrap, footer);
	modal.append(form);
	overlay.append(modal);
	document.body.append(overlay);

	const close = () => {
		overlay.remove();
	};

	const renderTypeFields = () => {
		dynamicSection.replaceChildren();
		const config = recordTypeConfig(typeInput.value);
		typedDescription.textContent = config.description;

		for (const field of config.fields) {
			dynamicSection.append(makeField(field));
		}

		rawWrap.classList.toggle("hidden", modeSelect.value !== "raw");
		dynamicSection.classList.toggle("hidden", modeSelect.value !== "typed");
		typedDescription.classList.toggle("hidden", modeSelect.value !== "typed");
	};

	closeButton.addEventListener("click", close);
	cancelButton.addEventListener("click", close);
	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) {
			close();
		}
	});

	modeSelect.addEventListener("change", renderTypeFields);
	typeInput.addEventListener("change", renderTypeFields);

	form.addEventListener("submit", async (event) => {
		event.preventDefault();

		try {
			const record = parseFormRecord(new FormData(form));
			await saveRecord(record, Boolean(currentRecord));
			close();
		} catch (err) {
			setStatus(err.message, true);
		}
	});

	renderTypeFields();
}

function createHeader() {
	const head = make("header", "top");
	const titleWrap = make("div", "title-wrap");
	const title = make("h1", "title");
	const subtitle = make("p", "subtitle");

	title.textContent = "plat DNS";
	subtitle.textContent = "Self-hosted DNS control for Cloudflare zones.";

	titleWrap.append(title, subtitle);
	head.append(titleWrap);

	if (state.authenticated) {
		const auth = make("div", "auth-chip");
		const text = make("span", "mono");
		const logout = make("button", "ghost");

		text.textContent = "Token active";
		logout.type = "button";
		logout.textContent = "Log out";
		logout.addEventListener("click", onLogoutClick);

		auth.append(text, logout);
		head.append(auth);
	}

	return head;
}

function createStatus() {
	const status = make("div", "status");

	if (!state.message && !state.error) {
		status.classList.add("hidden");
		return status;
	}

	status.classList.add(state.error ? "error" : "ok");
	status.textContent = state.error || state.message;

	return status;
}

function createLogin() {
	const panel = make("section", "panel", "login");
	const title = make("h2", "panel-title");
	const description = make("p", "panel-subtitle");
	const form = make("form", "stack");
	const tokenLabel = make("label", "field");
	const tokenTitle = make("span", "field-title");
	const tokenHint = make("span", "field-hint");
	const tokenInput = make("input", "input");
	const action = make("button", "button");

	title.textContent = "Access";
	description.textContent = "Use your server token to manage zones and records.";
	tokenTitle.textContent = "Token";
	tokenHint.textContent = "Stored in session storage and sent as Bearer token.";
	tokenInput.type = "password";
	tokenInput.name = "token";
	tokenInput.value = state.token;
	tokenInput.placeholder = "Paste access token";
	action.type = "submit";
	action.textContent = "Connect";

	tokenLabel.append(tokenTitle, tokenInput, tokenHint);
	form.append(tokenLabel, action);
	panel.append(title, description, form);

	form.addEventListener("submit", onLoginSubmit);

	return panel;
}

function createZones() {
	const panel = make("section", "panel", "zones");
	const top = make("div", "panel-head");
	const title = make("h2", "panel-title");
	const refresh = make("button", "ghost");
	const list = make("div", "zone-list");

	title.textContent = "Zones";
	refresh.type = "button";
	refresh.textContent = "Reload";
	refresh.addEventListener("click", onReloadInfoClick);

	top.append(title, refresh);
	panel.append(top, list);

	for (const zone of state.zones) {
		const button = make("button", "zone-item", zone === state.activeZone ? "active" : "");
		button.type = "button";
		button.textContent = zoneDisplay(zone);
		button.addEventListener("click", () => onZoneClick(zone));
		list.append(button);
	}

	return panel;
}

function createRecords() {
	const panel = make("section", "panel", "records");
	const top = make("div", "panel-head");
	const title = make("h2", "panel-title");
	const actions = make("div", "actions");
	const sync = make("button", "ghost");
	const add = make("button", "button");
	const table = make("table", "record-table");
	const head = make("thead");
	const body = make("tbody");

	title.textContent = state.activeZone ? `${zoneDisplay(state.activeZone)} records` : "Records";
	sync.type = "button";
	sync.textContent = "Sync from Cloudflare";
	add.type = "button";
	add.textContent = "New record";

	sync.disabled = !state.activeZone || state.loading;
	add.disabled = !state.activeZone || state.loading;

	sync.addEventListener("click", onSyncClick);
	add.addEventListener("click", onNewRecordClick);

	actions.append(sync, add);
	top.append(title, actions);
	panel.append(top);

	const headRow = make("tr");
	for (const label of ["Name", "Type", "Value", "TTL", ""]) {
		const th = make("th");
		th.textContent = label;
		headRow.append(th);
	}
	head.append(headRow);
	table.append(head, body);

	if (!state.activeZone) {
		const empty = make("p", "empty");
		empty.textContent = "No zone selected.";
		panel.append(empty);
		return panel;
	}

	if (!state.records.length) {
		const empty = make("p", "empty");
		empty.textContent = state.loading ? "Loading records..." : "No records in this zone yet.";
		panel.append(empty);
		return panel;
	}

	for (const record of state.records) {
		const row = make("tr");
		const name = make("td", "mono");
		const type = make("td", "mono");
		const value = make("td", "value");
		const ttl = make("td", "mono");
		const controls = make("td", "row-actions");
		const edit = make("button", "ghost");
		const del = make("button", "ghost", "danger");

		name.textContent = record.name;
		type.textContent = record.type;
		value.textContent = record.value;
		ttl.textContent = `${record.ttl}s`;
		edit.type = "button";
		edit.textContent = "Edit";
		del.type = "button";
		del.textContent = "Delete";

		edit.addEventListener("click", () => onEditRecordClick(record));
		del.addEventListener("click", () => onDeleteRecordClick(record));

		controls.append(edit, del);
		row.append(name, type, value, ttl, controls);
		body.append(row);
	}

	panel.append(table);

	const note = make("p", "note");
	note.textContent = "Current backend stores one record per name in each zone.";
	panel.append(note);

	return panel;
}

function createAuthed() {
	const layout = make("div", "layout");
	layout.append(createZones(), createRecords());
	return layout;
}

function render() {
	app.replaceChildren();
	const shell = make("main", "shell");

	shell.append(createHeader(), createStatus());
	shell.append(state.authenticated ? createAuthed() : createLogin());

	app.append(shell);
}

async function onLoginSubmit(event) {
	event.preventDefault();

	const formData = new FormData(event.currentTarget);
	const token = String(formData.get("token") || "").trim();

	if (!token) {
		setStatus("Token is required.", true);
		return;
	}

	state.token = token;
	sessionStorage.setItem(TOKEN_KEY, token);

	try {
		await checkInfo();
		if (!state.authenticated) {
			setStatus("Token is not valid.", true);
			return;
		}
		setStatus("Authenticated.", false);
	} catch (err) {
		setStatus(err.message, true);
	}
}

function onLogoutClick() {
	state.token = "";
	state.authenticated = false;
	state.zones = [];
	state.activeZone = "";
	state.records = [];
	state.message = "";
	state.error = "";
	sessionStorage.removeItem(TOKEN_KEY);
	render();
}

async function onReloadInfoClick() {
	try {
		await checkInfo();
		setStatus("Zone list updated.", false);
	} catch (err) {
		setStatus(err.message, true);
	}
}

async function onZoneClick(zone) {
	await loadZone(zone);
}

async function onSyncClick() {
	await refreshZoneFromCloudflare();
}

function onNewRecordClick() {
	openRecordModal();
}

function onEditRecordClick(record) {
	openRecordModal(record);
}

async function onDeleteRecordClick(record) {
	const okayDelete = window.confirm(`Delete ${record.name} (${record.type})?`);
	if (!okayDelete) {
		return;
	}

	try {
		await deleteRecord(record.name);
	} catch (err) {
		setStatus(err.message, true);
	}
}

async function init() {
	render();

	if (!state.token) {
		return;
	}

	try {
		await checkInfo();
		if (!state.authenticated) {
			sessionStorage.removeItem(TOKEN_KEY);
			state.token = "";
		}
		render();
	} catch (err) {
		setStatus(err.message, true);
	}
}

init();
