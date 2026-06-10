import "../css/plat.css";

const app = document.getElementById("app");

const RecordTypes = [
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

const state = {
	token: sessionStorage.getItem("plat-token") || "",
	theme: localStorage.getItem("plat-theme") || "dark",
	authenticated: false,
	zones: {},
	activeZone: "",
	records: [],
	loading: false,
	message: "",
	error: "",
};

const ui = {
	mounted: false,
	headerSlot: null,
	statusSlot: null,
	contentSlot: null,
	zonesSlot: null,
	recordsSlot: null,
	recordsScrollByZone: {},
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
	if (window.crypto?.getRandomValues) {
		const values = new Uint32Array(4);

		window.crypto.getRandomValues(values);

		return Array.from(values, value => value.toString(16).padStart(8, "0")).join("");
	}

	return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`;
}

function quote(value) {
	return JSON.stringify(String(value || ""));
}

function splitTokens(value) {
	const text = String(value || ""),
		fields = [];

	let current = "",
		inQuotes = false,
		escaped = false;

	for (const char of text) {
		if (escaped) {
			current += char;

			escaped = false;

			continue;
		}

		if (char === "\\") {
			escaped = true;

			continue;
		}

		if (char === '"') {
			inQuotes = !inQuotes;

			continue;
		}

		if (/\s/.test(char) && !inQuotes) {
			if (current) {
				fields.push(current);

				current = "";
			}

			continue;
		}

		current += char;
	}

	if (current) {
		fields.push(current);
	}

	return fields;
}

function parseByParts(value, keys) {
	const parts = splitTokens(value),
		result = {};

	for (let index = 0; index < keys.length; index += 1) {
		result[keys[index]] = parts[index] || "";
	}

	return result;
}

function parseWithRemainder(value, headKeys, tailKey) {
	const tokens = splitTokens(value),
		result = {};

	for (let index = 0; index < headKeys.length; index += 1) {
		result[headKeys[index]] = tokens[index] || "";
	}

	result[tailKey] = tokens.slice(headKeys.length).join(" ");

	return result;
}

function parseLoc(value) {
	const parts = splitTokens(value);

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
	const text = String(value || "").trim(),
		config = recordTypeConfig(type);

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
			build: data => data.address,
			parse: value => ({ address: value }),
		},
		AAAA: {
			description: "IPv6 address.",
			fields: [{ key: "address", label: "IPv6", placeholder: "2001:db8::5", required: true, hint: "A single IPv6 address." }],
			build: data => data.address,
			parse: value => ({ address: value }),
		},
		CNAME: {
			description: "Alias to another hostname.",
			fields: [{ key: "target", label: "Target", placeholder: "service.example.net.", required: true, hint: "Canonical target hostname.", wide: true }],
			build: data => data.target,
			parse: value => ({ target: value }),
		},
		NS: {
			description: "Delegated authoritative nameserver.",
			fields: [{ key: "host", label: "Nameserver", placeholder: "ns1.example.net.", required: true, hint: "Nameserver hostname." }],
			build: data => data.host,
			parse: value => ({ host: value }),
		},
		PTR: {
			description: "Reverse DNS pointer target.",
			fields: [{ key: "target", label: "Target", placeholder: "host.example.com.", required: true, hint: "Hostname returned by reverse lookup." }],
			build: data => data.target,
			parse: value => ({ target: value }),
		},
		TXT: {
			description: "Arbitrary text payload.",
			fields: [
				{
					key: "text",
					label: "Text",
					placeholder: "v=spf1 include:_spf.example.com ~all",
					required: true,
					hint: "Use raw text value.",
					multiline: true,
					wide: true,
					rows: 4,
				},
			],
			build: data => data.text,
			parse: value => ({ text: splitTokens(value).join(" ") }),
		},
		MX: {
			description: "Mail exchanger with priority.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "exchange", label: "Exchange", placeholder: "mail.example.com.", required: true, hint: "Mail server hostname." },
			],
			build: data => `${data.priority} ${data.exchange}`,
			parse: value => parseByParts(value, ["priority", "exchange"]),
		},
		CAA: {
			description: "Certificate Authority Authorization policy.",
			fields: [
				{ key: "flags", label: "Flags", placeholder: "0", required: true, hint: "0 for normal, 128 for critical." },
				{ key: "tag", label: "Tag", placeholder: "issue", required: true, hint: "issue, issuewild, or iodef." },
				{ key: "value", label: "Value", placeholder: "letsencrypt.org", required: true, hint: "CA domain or reporting URL." },
			],
			build: data => `${data.flags} ${data.tag} ${quote(data.value)}`,
			parse: value => parseWithRemainder(value, ["flags", "tag"], "value"),
		},
		SRV: {
			description: "Service location details.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values first." },
				{ key: "weight", label: "Weight", placeholder: "5", required: true, hint: "Relative balancing weight." },
				{ key: "port", label: "Port", placeholder: "443", required: true, hint: "Destination service port." },
				{ key: "target", label: "Target", placeholder: "service.example.com.", required: true, hint: "Destination hostname." },
			],
			build: data => `${data.priority} ${data.weight} ${data.port} ${data.target}`,
			parse: value => parseByParts(value, ["priority", "weight", "port", "target"]),
		},
		URI: {
			description: "Service URI with priority and weight.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "10", required: true, hint: "Lower values are preferred." },
				{ key: "weight", label: "Weight", placeholder: "1", required: true, hint: "Relative balancing weight." },
				{ key: "target", label: "Target URI", placeholder: "https://example.com/api", required: true, hint: "Quoted URI target." },
			],
			build: data => `${data.priority} ${data.weight} ${quote(data.target)}`,
			parse: value => parseWithRemainder(value, ["priority", "weight"], "target"),
		},
		TLSA: {
			description: "TLS certificate association data.",
			fields: [
				{ key: "usage", label: "Usage", placeholder: "3", required: true, hint: "Certificate usage selector." },
				{ key: "selector", label: "Selector", placeholder: "1", required: true, hint: "0 full cert, 1 subject public key." },
				{ key: "matching", label: "Matching Type", placeholder: "1", required: true, hint: "0 full, 1 SHA-256, 2 SHA-512." },
				{ key: "data", label: "Certificate Data", placeholder: "aabbcc...", required: true, hint: "Hex encoded association data." },
			],
			build: data => `${data.usage} ${data.selector} ${data.matching} ${data.data}`,
			parse: value => parseByParts(value, ["usage", "selector", "matching", "data"]),
		},
		SSHFP: {
			description: "SSH fingerprint metadata.",
			fields: [
				{ key: "algorithm", label: "Algorithm", placeholder: "4", required: true, hint: "1 RSA, 2 DSA, 3 ECDSA, 4 Ed25519." },
				{ key: "fpType", label: "Fingerprint Type", placeholder: "2", required: true, hint: "1 SHA-1 or 2 SHA-256." },
				{ key: "fingerprint", label: "Fingerprint", placeholder: "ab12...", required: true, hint: "Hex encoded fingerprint." },
			],
			build: data => `${data.algorithm} ${data.fpType} ${data.fingerprint}`,
			parse: value => parseByParts(value, ["algorithm", "fpType", "fingerprint"]),
		},
		DNSKEY: {
			description: "DNSSEC public key material.",
			fields: [
				{ key: "flags", label: "Flags", placeholder: "257", required: true, hint: "Commonly 256 (ZSK) or 257 (KSK)." },
				{ key: "protocol", label: "Protocol", placeholder: "3", required: true, hint: "Must be 3 for DNSSEC." },
				{ key: "algorithm", label: "Algorithm", placeholder: "13", required: true, hint: "DNSSEC signing algorithm." },
				{ key: "publicKey", label: "Public Key", placeholder: "AwEAA...", required: true, hint: "Base64 public key data." },
			],
			build: data => `${data.flags} ${data.protocol} ${data.algorithm} ${data.publicKey}`,
			parse: value => parseByParts(value, ["flags", "protocol", "algorithm", "publicKey"]),
		},
		DS: {
			description: "Delegation Signer digest.",
			fields: [
				{ key: "keyTag", label: "Key Tag", placeholder: "2371", required: true, hint: "Key identifier." },
				{ key: "algorithm", label: "Algorithm", placeholder: "13", required: true, hint: "DNSSEC algorithm number." },
				{ key: "digestType", label: "Digest Type", placeholder: "2", required: true, hint: "1 SHA-1, 2 SHA-256, 4 SHA-384." },
				{ key: "digest", label: "Digest", placeholder: "ab12...", required: true, hint: "Hex digest string." },
			],
			build: data => `${data.keyTag} ${data.algorithm} ${data.digestType} ${data.digest}`,
			parse: value => parseByParts(value, ["keyTag", "algorithm", "digestType", "digest"]),
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
			build: data => `${data.order} ${data.preference} ${quote(data.flags)} ${quote(data.service)} ${quote(data.regexp || "")} ${data.replacement}`,
			parse: value => parseByParts(value, ["order", "preference", "flags", "service", "regexp", "replacement"]),
		},
		CERT: {
			description: "Certificate record payload.",
			fields: [
				{ key: "certType", label: "Certificate Type", placeholder: "1", required: true, hint: "Numeric certificate type code." },
				{ key: "keyTag", label: "Key Tag", placeholder: "0", required: true, hint: "Associated key tag." },
				{ key: "algorithm", label: "Algorithm", placeholder: "0", required: true, hint: "Algorithm identifier." },
				{ key: "certificate", label: "Certificate", placeholder: "MIIB...", required: true, hint: "Base64 certificate data." },
			],
			build: data => `${data.certType} ${data.keyTag} ${data.algorithm} ${data.certificate}`,
			parse: value => parseByParts(value, ["certType", "keyTag", "algorithm", "certificate"]),
		},
		OPENPGPKEY: {
			description: "OpenPGP public key packet.",
			fields: [
				{ key: "packet", label: "Public Key Packet", placeholder: "mQENBF...", required: true, hint: "Base64 encoded packet body.", multiline: true, wide: true, rows: 5 },
			],
			build: data => data.packet,
			parse: value => ({ packet: value }),
		},
		SMIMEA: {
			description: "S/MIME certificate association.",
			fields: [
				{ key: "usage", label: "Usage", placeholder: "3", required: true, hint: "Certificate usage." },
				{ key: "selector", label: "Selector", placeholder: "1", required: true, hint: "Selector code." },
				{ key: "matching", label: "Matching Type", placeholder: "1", required: true, hint: "Digest or full match selector." },
				{ key: "data", label: "Certificate Data", placeholder: "aabb...", required: true, hint: "Hex association data." },
			],
			build: data => `${data.usage} ${data.selector} ${data.matching} ${data.data}`,
			parse: value => parseByParts(value, ["usage", "selector", "matching", "data"]),
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
			build: data => [data.lat, data.lng, data.alt, data.size, data.hPrec, data.vPrec].filter(Boolean).join(" "),
			parse: value => parseLoc(value),
		},
		HTTPS: {
			description: "HTTPS service binding (SVCB alias mode or service mode).",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: ".", required: true, hint: "Target name, usually . or a hostname." },
				{ key: "params", label: "Svc Params", placeholder: 'alpn="h3,h2" ipv4hint=203.0.113.5', required: false, hint: "Space-separated key=value parameters." },
			],
			build: data => [data.priority, data.target, data.params].filter(Boolean).join(" "),
			parse: value => parseWithRemainder(value, ["priority", "target"], "params"),
		},
		SVCB: {
			description: "Generic service binding record.",
			fields: [
				{ key: "priority", label: "Priority", placeholder: "1", required: true, hint: "0 for alias mode." },
				{ key: "target", label: "Target", placeholder: "svc.example.com.", required: true, hint: "Service target name." },
				{ key: "params", label: "Svc Params", placeholder: 'alpn="h2" port=443', required: false, hint: "Space-separated key=value parameters." },
			],
			build: data => [data.priority, data.target, data.params].filter(Boolean).join(" "),
			parse: value => parseWithRemainder(value, ["priority", "target"], "params"),
		},
	};

	return (
		map[type] || {
			description: "Raw record value.",
			fields: [{ key: "value", label: "Value", placeholder: "", required: true, hint: "Raw record value.", multiline: true, wide: true, rows: 4 }],
			build: data => data.value,
			parse: value => ({ value: value }),
		}
	);
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
	const raw = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";

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

	const nextHash = `${"#"}${encodeURIComponent(zone)}`;

	if (window.location.hash !== nextHash) {
		history.replaceState(null, "", `${window.location.pathname}${window.location.search}${nextHash}`);
	}
}

function setStatus(message, isError) {
	state.message = isError ? "" : message;
	state.error = isError ? message : "";

	renderStatus();
}

function applyTheme() {
	const theme = state.theme === "light" ? "light" : "dark";

	document.documentElement.setAttribute("data-theme", theme);

	state.theme = theme;

	localStorage.setItem("plat-theme", theme);
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
		headers: headers,
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

	renderZones();
	setActiveZoneSelection(true);

	await loadZone(state.activeZone);
}

async function loadZone(zone) {
	if (!zone) {
		state.records = [];
		setActiveZoneSelection(false);
		renderRecords();

		return;
	}

	const zoneChanged = state.activeZone !== zone;

	state.activeZone = zone;

	setZoneHash(zone);

	state.records = [];

	setActiveZoneSelection(zoneChanged);

	state.loading = true;

	renderRecords();

	try {
		const records = await api(`/-/${encodeURIComponent(zone)}`);

		state.records = Array.isArray(records) ? records : [];

		state.message = "";
		state.error = "";

		renderStatus();
	} catch (err) {
		state.records = [];
		state.error = err.message;

		renderStatus();
	} finally {
		state.loading = false;

		renderRecords();
		setActiveZoneSelection(zoneChanged);
	}
}

async function refreshZoneFromCloudflare() {
	if (!state.activeZone) {
		return;
	}

	state.loading = true;

	renderRecords();

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

		renderRecords();
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
	const mode = String(formData.get("mode") || "typed"),
		type = String(formData.get("type") || "A").toUpperCase(),
		name = String(formData.get("name") || "").trim(),
		ttl = Number.parseInt(String(formData.get("ttl") || "1"), 10);

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
		const config = recordTypeConfig(type),
			fieldData = {};

		for (const field of config.fields) {
			const key = `field_${field.key}`,
				current = String(formData.get(key) || "").trim();

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
		type: type,
		name: name,
		value: value,
		ttl: ttl,
	};
}

function makeField(field, current) {
	const wrap = make("label", "field", field.wide ? "field-wide" : ""),
		title = make("span", "field-title"),
		hint = make("span", "field-hint"),
		input = make(field.multiline ? "textarea" : "input", "input", field.multiline ? "textarea" : "");

	title.textContent = field.label;
	hint.textContent = field.hint || "";

	if (field.multiline) {
		input.rows = field.rows || 3;
	} else {
		input.type = "text";
	}

	input.name = `field_${field.key}`;
	input.placeholder = field.placeholder || "";
	input.value = current?.[field.key] || "";

	wrap.append(title, input, hint);

	return wrap;
}

function openRecordModal(currentRecord) {
	const overlay = make("div", "overlay"),
		modal = make("div", "modal"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		closeButton = make("button", "ghost"),
		form = make("form", "record-form"),
		modeRow = make("div", "inline-row"),
		modeLabel = make("span", "field-title"),
		modeSelect = make("select", "input"),
		rawWrap = make("label", "field"),
		rawTitle = make("span", "field-title"),
		rawHint = make("span", "field-hint"),
		rawInput = make("textarea", "input", "textarea"),
		dynamicSection = make("div", "dynamic-fields"),
		footer = make("div", "modal-foot"),
		submitButton = make("button", "button"),
		cancelButton = make("button", "ghost");

	title.textContent = currentRecord ? "Edit record" : "Create record";

	closeButton.type = "button";
	closeButton.textContent = "Close";

	modeLabel.textContent = "Input mode";

	const modeTyped = make("option"),
		modeRaw = make("option");

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

	const nameField = make("label", "field"),
		nameTitle = make("span", "field-title"),
		nameHint = make("span", "field-hint"),
		nameInput = make("input", "input");

	nameTitle.textContent = "Name";

	nameHint.textContent = "Use @ for zone root.";

	nameInput.type = "text";
	nameInput.name = "name";
	nameInput.placeholder = "@";
	nameInput.value = currentRecord?.name || "@";

	nameField.append(nameTitle, nameInput, nameHint);

	const typeField = make("label", "field"),
		typeTitle = make("span", "field-title"),
		typeHint = make("span", "field-hint"),
		typeInput = make("select", "input");

	typeTitle.textContent = "Type";

	typeHint.textContent = "All Cloudflare DNS record types are available.";

	typeInput.name = "type";

	for (const type of RecordTypes) {
		const option = make("option");

		option.value = type;
		option.textContent = type;

		typeInput.append(option);
	}

	typeInput.value = currentRecord?.type || "A";

	typeField.append(typeTitle, typeInput, typeHint);

	const ttlField = make("label", "field"),
		ttlTitle = make("span", "field-title"),
		ttlHint = make("span", "field-hint"),
		ttlInput = make("input", "input");

	ttlTitle.textContent = "TTL (seconds)";

	ttlHint.textContent = "Stored as integer seconds. Use 1 for auto.";

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

	const close = () => overlay.remove();

	let typedCache = parseRecordValue(typeInput.value, rawInput.value);

	const collectTypedFields = () => {
		const config = recordTypeConfig(typeInput.value),
			values = {};

		for (const field of config.fields) {
			const input = form.elements.namedItem(`field_${field.key}`);

			values[field.key] = input ? String(input.value || "").trim() : "";
		}

		return values;
	};

	const syncRawFromTyped = () => {
		const config = recordTypeConfig(typeInput.value),
			values = collectTypedFields();

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

	closeButton.addEventListener("click", close);
	cancelButton.addEventListener("click", close);

	overlay.addEventListener("click", event => {
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

	form.addEventListener("submit", async event => {
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
	const head = make("header", "top"),
		titleWrap = make("div", "title-wrap"),
		title = make("h1", "title");

	title.textContent = "plat";

	titleWrap.append(title);

	head.append(titleWrap);

	const controls = make("div", "top-controls"),
		theme = make("button", "ghost");

	theme.type = "button";
	theme.textContent = state.theme === "dark" ? "Light mode" : "Dark mode";
	theme.addEventListener("click", onThemeToggleClick);

	controls.append(theme);

	if (state.authenticated) {
		const logout = make("button", "ghost", "danger");

		logout.type = "button";
		logout.textContent = "Log out";
		logout.addEventListener("click", onLogoutClick);

		controls.append(logout);
	}

	head.append(controls);

	return head;
}

function createStatus() {
	const status = make("div", "status");

	if (!state.message && !state.error) {
		status.classList.add("idle");
		status.textContent = "Ready";

		return status;
	}

	status.classList.add(state.error ? "error" : "ok");
	status.textContent = state.error || state.message;

	return status;
}

function createLogin() {
	const panel = make("section", "panel", "login"),
		title = make("h2", "panel-title"),
		description = make("p", "panel-subtitle"),
		form = make("form", "stack"),
		tokenLabel = make("label", "field"),
		tokenTitle = make("span", "field-title"),
		tokenInput = make("input", "input"),
		action = make("button", "button");

	title.textContent = "Access";

	description.textContent = "Use your server token to manage zones and records.";

	tokenTitle.textContent = "Token";

	tokenInput.type = "password";
	tokenInput.name = "token";
	tokenInput.value = state.token;
	tokenInput.placeholder = "Paste access token";

	action.type = "submit";
	action.textContent = "Connect";

	tokenLabel.append(tokenTitle, tokenInput);

	form.append(tokenLabel, action);

	panel.append(title, description, form);

	form.addEventListener("submit", onLoginSubmit);

	return panel;
}

function createZones() {
	const panel = make("section", "panel", "zones"),
		top = make("div", "panel-head"),
		title = make("h2", "panel-title"),
		refresh = make("button", "ghost"),
		list = make("div", "zone-list");

	title.textContent = "Zones";

	refresh.type = "button";
	refresh.textContent = "Reload";
	refresh.addEventListener("click", onReloadInfoClick);

	top.append(title, refresh);

	panel.append(top, list);

	for (const [zoneId, zoneName] of zoneEntries()) {
		const button = make("button", "zone-item", zoneId === state.activeZone ? "active" : "");

		button.type = "button";
		button.dataset.zoneId = zoneId;
		button.textContent = zoneDisplay(zoneName);
		button.title = `${zoneDisplay(zoneName)} (${zoneId})`;
		button.addEventListener("click", () => onZoneClick(zoneId));

		list.append(button);
	}

	return panel;
}

function setActiveZoneSelection(ensureVisible = false) {
	if (!ui.zonesSlot) {
		return;
	}

	let activeButton = null;

	for (const button of ui.zonesSlot.querySelectorAll(".zone-item")) {
		const isActive = button.dataset.zoneId === state.activeZone;

		button.classList.toggle("active", isActive);

		if (isActive) {
			activeButton = button;
		}
	}

	if (ensureVisible && activeButton) {
		updateActiveZoneScroll();
	}
}

function updateActiveZoneScroll() {
	const activeButton = ui.zonesSlot?.querySelector(`.zone-item[data-zone-id="${state.activeZone}"]`);

	if (!activeButton) {
		return;
	}

	activeButton.scrollIntoView({
		block: "nearest",
		inline: "nearest",
	});
}

function saveScrollPosition(root, selector) {
	const element = root?.querySelector(selector);

	if (!element) {
		return null;
	}

	return {
		top: element.scrollTop,
		left: element.scrollLeft,
	};
}

function restoreScrollPosition(root, selector, position) {
	if (!position) {
		return;
	}

	const element = root?.querySelector(selector);

	if (!element) {
		return;
	}

	element.scrollTop = position.top;
	element.scrollLeft = position.left;
}

function createCell(text, classes = []) {
	const td = make("td", ...classes);

	td.textContent = text;

	if (text && text !== "--") {
		td.title = text;
	}

	return td;
}

function displayRecordName(record, zoneName) {
	if (record.name === "@") {
		return zoneDisplay(zoneName || "@");
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

	return "--";
}

function recordDetails(record) {
	const parts = splitTokens(record.value);

	switch (record.type) {
		case "MX":
			return parts[0] ? `priority ${parts[0]}` : "--";
		case "SRV":
			if (parts.length >= 3) {
				return `prio ${parts[0]} weight ${parts[1]} port ${parts[2]}`;
			}

			return "--";
		case "URI":
			if (parts.length >= 2) {
				return `prio ${parts[0]} weight ${parts[1]}`;
			}

			return "--";
		case "CAA":
			if (parts.length >= 2) {
				return `flags ${parts[0]} tag ${parts[1]}`;
			}

			return "--";
		case "TLSA":
		case "SMIMEA":
			if (parts.length >= 3) {
				return `u ${parts[0]} s ${parts[1]} m ${parts[2]}`;
			}

			return "--";
		default:
			return "--";
	}
}

function createRecords() {
	const panel = make("section", "panel", "records"),
		top = make("div", "panel-head"),
		title = make("h2", "panel-title"),
		actions = make("div", "actions"),
		sync = make("button", "ghost"),
		add = make("button", "button"),
		tableWrap = make("div", "table-wrap"),
		table = make("table", "record-table"),
		colgroup = make("colgroup"),
		head = make("thead"),
		body = make("tbody");

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
		const row = make("tr"),
			controls = make("td", "row-actions", "w-actions"),
			edit = make("button", "ghost"),
			del = make("button", "ghost", "danger");

		row.append(
			createCell(displayRecordName(record, activeZoneName()), ["mono", "w-name"]),
			createCell(record.type, ["mono", "w-type"]),
			createCell(record.value, ["value", "w-content"]),
			createCell(!record.ttl || record.ttl === 1 ? "auto" : `${record.ttl}s`, ["mono", "w-ttl"]),
			createCell(recordTags(record), ["w-tags"]),
			createCell(recordDetails(record), ["mono", "w-details"])
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

	return panel;
}

function mountShell() {
	if (ui.mounted) {
		return;
	}

	const shell = make("main", "shell");

	ui.headerSlot = make("div", "header-slot");
	ui.statusSlot = make("div", "status-slot");
	ui.contentSlot = make("div", "content-slot");

	shell.append(ui.headerSlot, ui.statusSlot, ui.contentSlot);

	app.append(shell);

	ui.mounted = true;
}

function clearAuthedSlots() {
	ui.zonesSlot = null;
	ui.recordsSlot = null;
	ui.recordsScrollByZone = {};
}

function ensureAuthedLayout() {
	if (ui.zonesSlot && ui.recordsSlot) {
		return;
	}

	const layout = make("div", "layout");

	ui.zonesSlot = make("div", "zones-slot");
	ui.recordsSlot = make("div", "records-slot");

	layout.append(ui.zonesSlot, ui.recordsSlot);

	ui.contentSlot.replaceChildren(layout);
}

function renderHeader() {
	if (!ui.mounted) {
		return;
	}

	ui.headerSlot.replaceChildren(createHeader());
}

function renderStatus() {
	if (!ui.mounted) {
		return;
	}

	ui.statusSlot.replaceChildren(createStatus());
}

function renderZones() {
	if (!ui.mounted || !state.authenticated) {
		return;
	}

	ensureAuthedLayout();
	const scrollPosition = saveScrollPosition(ui.zonesSlot, ".zone-list");

	ui.zonesSlot.replaceChildren(createZones());

	restoreScrollPosition(ui.zonesSlot, ".zone-list", scrollPosition);
}

function renderRecords() {
	if (!ui.mounted || !state.authenticated) {
		return;
	}

	ensureAuthedLayout();

	const scrollPosition = saveScrollPosition(ui.recordsSlot, ".table-wrap"),
		zoneId = state.activeZone;

	if (scrollPosition && zoneId) {
		ui.recordsScrollByZone[zoneId] = scrollPosition;
	}

	ui.recordsSlot.replaceChildren(createRecords());

	restoreScrollPosition(ui.recordsSlot, ".table-wrap", scrollPosition || ui.recordsScrollByZone[zoneId] || null);
}

function renderAuthedPanels() {
	renderZones();
	renderRecords();
}

function renderContent() {
	if (!ui.mounted) {
		return;
	}

	if (!state.authenticated) {
		clearAuthedSlots();

		ui.contentSlot.replaceChildren(createLogin());

		return;
	}

	ensureAuthedLayout();
	renderAuthedPanels();
}

function render() {
	applyTheme();
	mountShell();
	renderHeader();
	renderStatus();
	renderContent();
}

async function onLoginSubmit(event) {
	event.preventDefault();

	const formData = new FormData(event.currentTarget),
		token = String(formData.get("token") || "").trim();

	if (!token) {
		setStatus("Token is required.", true);

		return;
	}

	state.token = token;

	sessionStorage.setItem("plat-token", token);

	try {
		await checkInfo();

		if (!state.authenticated) {
			setStatus("Token is not valid.", true);

			return;
		}

		render();

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

	sessionStorage.removeItem("plat-token");

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
	window.addEventListener("load", updateActiveZoneScroll);

	if (document.fonts?.ready) {
		document.fonts.ready.then(updateActiveZoneScroll);
	}

	render();

	if (!state.token) {
		return;
	}

	try {
		await checkInfo();

		if (!state.authenticated) {
			sessionStorage.removeItem("plat-token");

			state.token = "";
		}

		render();
	} catch (err) {
		setStatus(err.message, true);
	}
}

init();
