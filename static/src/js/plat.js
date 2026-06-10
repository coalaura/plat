import "../css/plat.css";

const app = document.getElementById("app");

const TOKEN_KEY = "plat-token";
const THEME_KEY = "plat-theme";
const ROOT_LABEL = "@";
const DEFAULT_THEME = "dark";
const EMPTY = "--";
const HASH_PREFIX = "#";

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
	theme: localStorage.getItem(THEME_KEY) || DEFAULT_THEME,
	authenticated: false,
	zones: {},
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

function randomId() {
	if (window.crypto && window.crypto.getRandomValues) {
		const values = new Uint32Array(4);
		window.crypto.getRandomValues(values);
		return Array.from(values, (value) => value.toString(16).padStart(8, "0")).join("");
	}

	return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`;
}

function quote(value) {
	if (!value) {
		return "\"\"";
	}

	const clean = String(value).trim().replace(/"/g, '\\"');

	if (clean.startsWith("\"") && clean.endsWith("\"")) {
		return clean;
	}

	return `"${clean}"`;
}

function unquote(value) {
	const text = String(value || "").trim();
	if (!text) {
		return "";
	}

	if (text.startsWith("\"") && text.endsWith("\"") && text.length >= 2) {
		return text.slice(1, -1).replace(/\\"/g, '"');
	}

	return text;
}

function splitTokens(value) {
	const text = String(value || "").trim();
	if (!text) {
		return [];
	}

	const matches = text.match(/"(?:\\"|[^"])*"|\S+/g);
	return matches || [];
}

function parseByParts(value, keys) {
	const parts = splitTokens(value).map(unquote);
	const result = {};

	for (let index = 0; index < keys.length; index += 1) {
		result[keys[index]] = parts[index] || "";
	}

	return result;
}

function parseWithRemainder(value, headKeys, tailKey) {
	const tokens = splitTokens(value);
	const result = {};

	for (let index = 0; index < headKeys.length; index += 1) {
		result[headKeys[index]] = unquote(tokens[index] || "");
	}

	const rest = tokens.slice(headKeys.length).join(" ");
	result[tailKey] = unquote(rest);

	return result;
}

function parseLoc(value) {
	const parts = splitTokens(value).map(unquote);
	return {
		lat: parts.slice(0, 4).join(" "),
		lng: parts.slice(4, 8).join(" "),
		alt: parts[8] || "",
		size: parts[9] || "",
		hPrec: parts[10] || "",
		vPrec: parts[11] || "",
	};
}

function parseRecordValue(type, value) {
	const text = String(value || "").trim();
	const config = recordTypeConfig(type);

	try {
		const parsed = config.parse(text);
		if (parsed && typeof parsed === "object") {
			return parsed;
		}
	} catch {
		return {};
	}

	return {};
}

function recordTypeConfig(type) {
	const map = {
		A: {
			description: "IPv4 address.",
			fields: [{ key: "address", label: "IPv4", placeholder: "203.0.113.5", required: true, hint: "A single IPv4 address." }],
			build: (data) => data.address,
			parse: (value) => ({ address: value }),
		},
		AAAA: {
			description: "IPv6 address.",
			fields: [{ key: "address", label: "IPv6", placeholder: "2001:db8::5", required: true, hint: "A single IPv6 address." }],
			build: (data) => data.address,
			parse: (value) => ({ address: value }),
		},
		CNAME: {
			description: "Alias to another hostname.",
			fields: [{ key: "target", label: "Target", placeholder: "service.example.net.", required: true, hint: "Canonical target hostname.", wide: true }],
			build: (data) => data.target,
			parse: (value) => ({ target: value }),
		},
		NS: {
			description: "Delegated authoritative nameserver.",
			fields: [{ key: "host", label: "Nameserver", placeholder: "ns1.example.net.", required: true, hint: "Nameserver hostname." }],
			build: (data) => data.host,
			parse: (value) => ({ host: value }),
		},
		PTR: {
			description: "Reverse DNS pointer target.",
			fields: [{ key: "target", label: "Target", placeholder: "host.example.com.", required: true, hint: "Hostname returned by reverse lookup." }],
			build: (data) => data.target,
			parse: (value) => ({ target: value }),
		},
		TXT: {
			description: "Arbitrary text payload.",
			fields: [{ key: "text", label: "Text", placeholder: "v=spf1 include:_spf.example.com ~all", required: true, hint: "Use raw text value.", multiline: true, wide: true, rows: 4 }],
			build: (data) => data.text,
			parse: (value) => ({ text: unquote(value) }),
		},
		MX: {
			description: "Mail exchanger with priority.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "exchange", label: "Exchange", placeholder: "mail.example.com.", required: true, hint: "Mail server hostname." },
			],
			build: (data) => `${data.priority} ${data.exchange}`,
			parse: (value) => parseByParts(value, ["priority", "exchange"]),
		},
		CAA: {
			description: "Certificate Authority Authorization policy.",
			fields: [
				{ key: "flags", label: "Flags", placeholder: "0", required: true, hint: "0 for normal, 128 for critical." },
				{ key: "tag", label: "Tag", placeholder: "issue", required: true, hint: "issue, issuewild, or iodef." },
				{ key: "value", label: "Value", placeholder: "letsencrypt.org", required: true, hint: "CA domain or reporting URL." },
			],
			build: (data) => `${data.flags} ${data.tag} ${quote(data.value)}`,
			parse: (value) => parseWithRemainder(value, ["flags", "tag"], "value"),
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
			parse: (value) => parseByParts(value, ["priority", "weight", "port", "target"]),
		},
		URI: {
			description: "Service URI with priority and weight.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "weight", label: "Weight", placeholder: "1", required: true, hint: "Relative balancing weight." },
				{ key: "target", label: "Target URI", placeholder: "https://example.com/api", required: true, hint: "Quoted URI target." },
			],
			build: (data) => `${data.priority} ${data.weight} ${quote(data.target)}`,
			parse: (value) => parseWithRemainder(value, ["priority", "weight"], "target"),
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
			parse: (value) => parseByParts(value, ["usage", "selector", "matching", "data"]),
		},
		SSHFP: {
			description: "SSH fingerprint metadata.",
			fields: [
				{ key: "algorithm", label: "Algorithm", placeholder: "4", required: true, hint: "1 RSA, 2 DSA, 3 ECDSA, 4 Ed25519." },
				{ key: "fpType", label: "Fingerprint Type", placeholder: "2", required: true, hint: "1 SHA-1 or 2 SHA-256." },
				{ key: "fingerprint", label: "Fingerprint", placeholder: "ab12...", required: true, hint: "Hex encoded fingerprint." },
			],
			build: (data) => `${data.algorithm} ${data.fpType} ${data.fingerprint}`,
			parse: (value) => parseByParts(value, ["algorithm", "fpType", "fingerprint"]),
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
			parse: (value) => parseByParts(value, ["flags", "protocol", "algorithm", "publicKey"]),
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
			parse: (value) => parseByParts(value, ["keyTag", "algorithm", "digestType", "digest"]),
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
			parse: (value) => parseByParts(value, ["order", "preference", "flags", "service", "regexp", "replacement"]),
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
			parse: (value) => parseByParts(value, ["certType", "keyTag", "algorithm", "certificate"]),
		},
		OPENPGPKEY: {
			description: "OpenPGP public key packet.",
			fields: [{ key: "packet", label: "Public Key Packet", placeholder: "mQENBF...", required: true, hint: "Base64 encoded packet body.", multiline: true, wide: true, rows: 5 }],
			build: (data) => data.packet,
			parse: (value) => ({ packet: value }),
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
			parse: (value) => parseByParts(value, ["usage", "selector", "matching", "data"]),
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
			parse: (value) => parseLoc(value),
		},
		HTTPS: {
			description: "HTTPS service binding (SVCB alias mode or service mode).",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: ".", required: true, hint: "Target name, usually . or a hostname." },
				{ key: "params", label: "Svc Params", placeholder: "alpn=\"h3,h2\" ipv4hint=203.0.113.5", required: false, hint: "Space-separated key=value parameters." },
			],
			build: (data) => [data.priority, data.target, data.params].filter(Boolean).join(" "),
			parse: (value) => parseWithRemainder(value, ["priority", "target"], "params"),
		},
		SVCB: {
			description: "Generic service binding record.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: "svc.example.com.", required: true, hint: "Service target name." },
				{ key: "params", label: "Svc Params", placeholder: "alpn=\"h2\" port=443", required: false, hint: "Space-separated key=value parameters." },
			],
			build: (data) => [data.priority, data.target, data.params].filter(Boolean).join(" "),
			parse: (value) => parseWithRemainder(value, ["priority", "target"], "params"),
		},
	};

	return map[type] || {
		description: "Raw record value.",
		fields: [{ key: "value", label: "Value", placeholder: "", required: true, hint: "Raw record value.", multiline: true, wide: true, rows: 4 }],
		build: (data) => data.value,
		parse: (value) => ({ value }),
	};
}

function zoneDisplay(zone) {
	return zone.endsWith(".") ? zone.slice(0, -1) : zone;
}

function zoneEntries() {
	return Object.entries(state.zones).sort((a, b) => {
		const nameSort = zoneDisplay(a[1]).localeCompare(zoneDisplay(b[1]));
		if (nameSort !== 0) {
			return nameSort;
		}

		return a[0].localeCompare(b[0]);
	});
}

function activeZoneName() {
	return state.zones[state.activeZone] || "";
}

function zoneFromHash() {
	const raw = window.location.hash.startsWith(HASH_PREFIX) ? window.location.hash.slice(1) : "";
	if (!raw) {
		return "";
	}

	try {
		return decodeURIComponent(raw);
	} catch {
		return "";
	}
}

function setZoneHash(zone) {
	if (!zone) {
		if (window.location.hash) {
			history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
		}
		return;
	}

	const nextHash = `${HASH_PREFIX}${encodeURIComponent(zone)}`;
	if (window.location.hash !== nextHash) {
		history.replaceState(null, "", `${window.location.pathname}${window.location.search}${nextHash}`);
	}
}

function setStatus(message, isError) {
	state.message = isError ? "" : message;
	state.error = isError ? message : "";
	render();
}

function applyTheme() {
	const theme = state.theme === "light" ? "light" : "dark";
	document.documentElement.setAttribute("data-theme", theme);
	state.theme = theme;
	localStorage.setItem(THEME_KEY, theme);
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
	const zones = info?.zones;
	state.zones = zones && typeof zones === "object" && !Array.isArray(zones) ? zones : {};

	if (!state.authenticated) {
		state.activeZone = "";
		state.records = [];
		return;
	}

	if (!Object.keys(state.zones).length) {
		state.activeZone = "";
		state.records = [];
		return;
	}

	const hashZone = zoneFromHash();
	if (hashZone && state.zones[hashZone]) {
		state.activeZone = hashZone;
	} else if (!state.activeZone || !state.zones[state.activeZone]) {
		state.activeZone = zoneEntries()[0][0];
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
		const records = await api(`/-/${encodeURIComponent(zone)}`);
		state.records = Array.isArray(records) ? records : [];
		state.activeZone = zone;
		setZoneHash(zone);
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
		const records = await api(`/-/${encodeURIComponent(state.activeZone)}`, {
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
	await api(`/-/${encodeURIComponent(state.activeZone)}`, {
		method: isUpdate ? "PUT" : "POST",
		body: JSON.stringify(record),
	});

	setStatus(isUpdate ? "Record updated." : "Record created.", false);
	await loadZone(state.activeZone);
}

async function deleteRecord(record) {
	await api(`/-/${encodeURIComponent(state.activeZone)}/${encodeURIComponent(record.id)}`, {
		method: "DELETE",
	});

	setStatus(`Deleted ${record.name} (${record.type}).`, false);
	await loadZone(state.activeZone);
}

function parseFormRecord(formData, currentRecord) {
	const mode = String(formData.get("mode") || "typed");
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
		id: currentRecord?.id || randomId(),
		type,
		name,
		value,
		ttl,
	};
}

function makeField(field, current) {
	const wrap = make("label", "field", field.wide ? "field-wide" : "");
	const title = make("span", "field-title");
	const hint = make("span", "field-hint");
	const input = make(field.multiline ? "textarea" : "input", "input", field.multiline ? "textarea" : "");

	title.textContent = field.label;
	hint.textContent = field.hint || "";

	if (!field.multiline) {
		input.type = "text";
	} else {
		input.rows = field.rows || 3;
	}
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
	modeSelect.value = "typed";

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

	let typedCache = parseRecordValue(typeInput.value, rawInput.value);

	const collectTypedFields = () => {
		const config = recordTypeConfig(typeInput.value);
		const values = {};
		for (const field of config.fields) {
			const input = form.elements.namedItem(`field_${field.key}`);
			values[field.key] = input ? String(input.value || "").trim() : "";
		}
		return values;
	};

	const syncRawFromTyped = () => {
		const config = recordTypeConfig(typeInput.value);
		const values = collectTypedFields();
		typedCache = values;
		rawInput.value = config.build(values).trim();
	};

	const syncTypedFromRaw = () => {
		typedCache = parseRecordValue(typeInput.value, rawInput.value);
	};

	const renderTypeFields = () => {
		dynamicSection.replaceChildren();
		const config = recordTypeConfig(typeInput.value);
		typedDescription.textContent = config.description;

		for (const field of config.fields) {
			dynamicSection.append(makeField(field, typedCache));
		}

		rawWrap.classList.toggle("hidden", modeSelect.value !== "raw");
		dynamicSection.classList.toggle("hidden", modeSelect.value !== "typed");
		typedDescription.classList.toggle("hidden", modeSelect.value !== "typed");
	};

	const close = () => {
		overlay.remove();
	};

	closeButton.addEventListener("click", close);
	cancelButton.addEventListener("click", close);
	overlay.addEventListener("click", (event) => {
		if (event.target === overlay) {
			close();
		}
	});

	modeSelect.addEventListener("change", () => {
		if (modeSelect.value === "raw") {
			syncRawFromTyped();
		} else {
			syncTypedFromRaw();
		}
		renderTypeFields();
	});

	typeInput.addEventListener("change", () => {
		if (modeSelect.value === "raw") {
			syncTypedFromRaw();
		} else {
			typedCache = collectTypedFields();
		}
		renderTypeFields();
	});

	form.addEventListener("submit", async (event) => {
		event.preventDefault();

		try {
			if (modeSelect.value === "raw") {
				syncTypedFromRaw();
			} else {
				syncRawFromTyped();
			}

			const record = parseFormRecord(new FormData(form), currentRecord);
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

	const controls = make("div", "top-controls");
	const theme = make("button", "ghost");
	theme.type = "button";
	theme.textContent = state.theme === "dark" ? "Light mode" : "Dark mode";
	theme.addEventListener("click", onThemeToggleClick);
	controls.append(theme);

	if (state.authenticated) {
		const auth = make("div", "auth-chip");
		const text = make("span", "mono");
		const logout = make("button", "ghost");

		text.textContent = "Token active";
		logout.type = "button";
		logout.textContent = "Log out";
		logout.addEventListener("click", onLogoutClick);

		auth.append(text, logout);
		controls.append(auth);
	}

	head.append(controls);

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

	for (const [zoneId, zoneName] of zoneEntries()) {
		const button = make("button", "zone-item", zoneId === state.activeZone ? "active" : "");
		button.type = "button";
		button.textContent = zoneDisplay(zoneName);
		button.title = `${zoneDisplay(zoneName)} (${zoneId})`;
		button.addEventListener("click", () => onZoneClick(zoneId));
		list.append(button);
	}

	return panel;
}

function createCell(text, classes = []) {
	const td = make("td", ...classes);
	td.textContent = text;
	if (text && text !== EMPTY) {
		td.title = text;
	}
	return td;
}

function displayRecordName(record, zoneName) {
	if (record.name === ROOT_LABEL) {
		return zoneDisplay(zoneName || ROOT_LABEL);
	}

	return record.name;
}

function recordTags(record) {
	if (Array.isArray(record.tags) && record.tags.length) {
		return record.tags.join(", ");
	}

	if (typeof record.tags === "string" && record.tags.trim()) {
		return record.tags.trim();
	}

	return EMPTY;
}

function recordDetails(record) {
	const parts = splitTokens(record.value).map(unquote);

	switch (record.type) {
		case "MX":
			return parts[0] ? `priority ${parts[0]}` : EMPTY;
		case "SRV":
			if (parts.length >= 3) {
				return `prio ${parts[0]} weight ${parts[1]} port ${parts[2]}`;
			}
			return EMPTY;
		case "URI":
			if (parts.length >= 2) {
				return `prio ${parts[0]} weight ${parts[1]}`;
			}
			return EMPTY;
		case "CAA":
			if (parts.length >= 2) {
				return `flags ${parts[0]} tag ${parts[1]}`;
			}
			return EMPTY;
		case "TLSA":
		case "SMIMEA":
			if (parts.length >= 3) {
				return `u ${parts[0]} s ${parts[1]} m ${parts[2]}`;
			}
			return EMPTY;
		default:
			return EMPTY;
	}
}

function createRecords() {
	const panel = make("section", "panel", "records");
	const top = make("div", "panel-head");
	const title = make("h2", "panel-title");
	const actions = make("div", "actions");
	const sync = make("button", "ghost");
	const add = make("button", "button");
	const tableWrap = make("div", "table-wrap");
	const table = make("table", "record-table");
	const colgroup = make("colgroup");
	const head = make("thead");
	const body = make("tbody");

	title.textContent = state.activeZone ? `${zoneDisplay(activeZoneName())} records` : "Records";
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

	for (const colClass of ["col-name", "col-type", "col-content", "col-ttl", "col-tags", "col-details", "col-actions"]) {
		const col = make("col", colClass);
		colgroup.append(col);
	}

	const headRow = make("tr");
	for (const label of ["Name", "Type", "Content", "TTL", "Tags", "Details", "Actions"]) {
		const th = make("th");
		th.textContent = label;
		headRow.append(th);
	}
	head.append(headRow);
	table.append(colgroup, head, body);

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
		const controls = make("td", "row-actions", "w-actions");
		const edit = make("button", "ghost");
		const del = make("button", "ghost", "danger");

		row.append(
			createCell(displayRecordName(record, activeZoneName()), ["mono", "w-name"]),
			createCell(record.type, ["mono", "w-type"]),
			createCell(record.value, ["value", "w-content"]),
			createCell(record.ttl ? `${record.ttl}s` : "auto", ["mono", "w-ttl"]),
			createCell(recordTags(record), ["w-tags"]),
			createCell(recordDetails(record), ["mono", "w-details"]),
		);

		edit.type = "button";
		edit.textContent = "Edit";
		del.type = "button";
		del.textContent = "Delete";

		edit.addEventListener("click", () => onEditRecordClick(record));
		del.addEventListener("click", () => onDeleteRecordClick(record));

		controls.append(edit, del);
		row.append(controls);
		body.append(row);
	}

	tableWrap.append(table);
	panel.append(tableWrap);

	const note = make("p", "note");
	note.textContent = "Delete and update actions now target the record id.";
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
	applyTheme();

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

function onThemeToggleClick() {
	state.theme = state.theme === "dark" ? "light" : "dark";
	render();
}

function onLogoutClick() {
	state.token = "";
	state.authenticated = false;
	state.zones = {};
	state.activeZone = "";
	state.records = [];
	state.message = "";
	state.error = "";
	sessionStorage.removeItem(TOKEN_KEY);
	setZoneHash("");
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

async function onHashChange() {
	if (!state.authenticated) {
		return;
	}

	const hashZone = zoneFromHash();
	if (!hashZone || hashZone === state.activeZone || !state.zones[hashZone]) {
		return;
	}

	await loadZone(hashZone);
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
		await deleteRecord(record);
	} catch (err) {
		setStatus(err.message, true);
	}
}

async function init() {
	window.addEventListener("hashchange", onHashChange);

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
