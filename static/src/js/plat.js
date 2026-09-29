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
	cloudflare: false,
	zones: {},
	activeZone: "",
	records: [],
	loadingRecords: false,
	syncingRecords: false,
	savingRecord: false,
	deletingRecordId: "",
	reloadingZones: false,
	fetchingAllRecords: false,
	dyndnsUsers: [],
	loadingDynDNSUsers: false,
	savingDynDNSUser: false,
	deletingDynDNSUsername: "",
	activeWorkspace: "records",
};

const ui = {
	mounted: false,
	headerSlot: null,
	contentSlot: null,
	zonesSlot: null,
	workspaceSlot: null,
	workspaceTabs: null,
	recordsSlot: null,
	dyndnsSlot: null,
	recordsScrollByZone: {},
	notificationItems: new Map(),
	notificationTimers: new Map(),
	notificationRoot: null,
	fetchAllOverlay: null,
	fetchAllSummary: null,
	fetchAllLog: null,
	fetchAllProgressBar: null,
	fetchAllProgressText: null,
	fetchAllCloseButton: null,
	fetchAllCancelButton: null,
	fetchAllAbortController: null,
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

function decodeTXT(str) {
	str = String(str || "").trim();

	if (!str.startsWith('"')) {
		return str;
	}

	let result = "",
		inQuotes = false,
		escaped = false;

	for (const char of str) {
		if (escaped) {
			result += char;

			escaped = false;

			continue;
		}

		if (inQuotes && char === "\\") {
			escaped = true;
		} else if (char === '"') {
			inQuotes = !inQuotes;
		} else if (inQuotes) {
			result += char;
		}
	}

	return result;
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

	let pos = 0;

	const readCoord = (dir1, dir2) => {
		const start = pos;

		while (pos < parts.length) {
			const tok = parts[pos].toUpperCase();

			if (tok === dir1 || tok === dir2) {
				pos++;

				break;
			}

			pos++;
		}

		return parts.slice(start, pos).join(" ");
	};

	const lat = readCoord("N", "S"),
		lng = readCoord("E", "W"),
		alt = parts[pos++] || "",
		size = parts[pos++] || "",
		hPrec = parts[pos++] || "",
		vPrec = parts[pos++] || "";

	return {
		lat: lat,
		lng: lng,
		alt: alt,
		size: size,
		hPrec: hPrec,
		vPrec: vPrec,
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
			build: data => quote(data.text),
			parse: value => ({ text: decodeTXT(value) }),
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
			build: data => `${data.flags} ${data.tag} ${quote(data.content)}`,
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
				{ key: "algorithm", label: "Algorithm", placeholder: "15", required: true, hint: "DNSSEC signing algorithm." },
				{ key: "publicKey", label: "Public Key", placeholder: "AwEAA...", required: true, hint: "Base64 public key data." },
			],
			build: data => `${data.flags} ${data.protocol} ${data.algorithm} ${data.publicKey}`,
			parse: value => parseByParts(value, ["flags", "protocol", "algorithm", "publicKey"]),
		},
		DS: {
			description: "Delegation Signer digest.",
			fields: [
				{ key: "keyTag", label: "Key Tag", placeholder: "2371", required: true, hint: "Key identifier." },
				{ key: "algorithm", label: "Algorithm", placeholder: "15", required: true, hint: "DNSSEC algorithm number." },
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
			build: data => data.content,
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

function activeZoneIsLocal() {
	return state.activeZone.startsWith("local-");
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
	if (!message) {
		return;
	}

	const notification = createNotification({
		id: randomId(),
		text: String(message),
		type: isError ? "error" : "ok",
	});

	ui.notificationRoot.append(notification.element);
	ui.notificationItems.set(notification.id, notification.element);

	const timeout = window.setTimeout(() => dismissNotification(notification.id), isError ? 7000 : 4500);

	ui.notificationTimers.set(notification.id, timeout);
}

function ensureNotificationRoot() {
	if (ui.notificationRoot) {
		return;
	}

	const root = make("div", "notifications");

	root.setAttribute("aria-live", "polite");
	root.setAttribute("aria-atomic", "false");

	document.body.append(root);

	ui.notificationRoot = root;
}

function createNotification(notification) {
	ensureNotificationRoot();

	const item = make("div", "notification", notification.type),
		text = make("p", "notification-text"),
		dismiss = make("button", "notification-dismiss");

	text.textContent = notification.text;

	dismiss.type = "button";
	dismiss.textContent = "Dismiss";
	dismiss.addEventListener("click", () => dismissNotification(notification.id));

	item.append(text, dismiss);

	return {
		id: notification.id,
		element: item,
	};
}

function dismissNotification(id) {
	const timeout = ui.notificationTimers.get(id);

	if (timeout) {
		clearTimeout(timeout);

		ui.notificationTimers.delete(id);
	}

	const item = ui.notificationItems.get(id);

	if (!item) {
		return;
	}

	item.remove();

	ui.notificationItems.delete(id);
}

function clearNotifications() {
	for (const timeout of ui.notificationTimers.values()) {
		clearTimeout(timeout);
	}

	ui.notificationTimers.clear();

	for (const item of ui.notificationItems.values()) {
		item.remove();
	}

	ui.notificationItems.clear();

	if (ui.notificationRoot) {
		ui.notificationRoot.remove();
		ui.notificationRoot = null;
	}
}

function ensureFetchAllOverlay() {
	if (ui.fetchAllOverlay) {
		return;
	}

	const overlay = make("div", "fetch-all-overlay"),
		panel = make("div", "fetch-all-panel"),
		title = make("h2", "fetch-all-title"),
		summary = make("p", "fetch-all-summary"),
		progress = make("div", "fetch-all-progress"),
		progressBar = make("div", "fetch-all-progress-bar"),
		progressFill = make("div", "fetch-all-progress-fill"),
		progressText = make("p", "fetch-all-progress-text"),
		log = make("p", "fetch-all-log"),
		actions = make("div", "fetch-all-actions"),
		cancelButton = make("button", "ghost", "danger"),
		closeButton = make("button", "ghost");

	title.textContent = "Fetching all zones";

	cancelButton.type = "button";
	cancelButton.textContent = "Cancel";
	cancelButton.addEventListener("click", onFetchAllCancelClick);

	closeButton.type = "button";
	closeButton.textContent = "Close";
	closeButton.addEventListener("click", closeFetchAllOverlay);

	progressBar.append(progressFill);

	progress.append(progressBar, progressText);

	actions.append(cancelButton, closeButton);

	panel.append(title, summary, progress, log, actions);

	overlay.append(panel);

	document.body.append(overlay);

	ui.fetchAllOverlay = overlay;
	ui.fetchAllSummary = summary;
	ui.fetchAllLog = log;
	ui.fetchAllProgressBar = progressFill;
	ui.fetchAllProgressText = progressText;
	ui.fetchAllCloseButton = closeButton;
	ui.fetchAllCancelButton = cancelButton;
}

function openFetchAllOverlay() {
	ensureFetchAllOverlay();

	ui.fetchAllOverlay.classList.remove("ok", "error");
	ui.fetchAllOverlay.classList.add("running");
	ui.fetchAllSummary.textContent = "Starting full sync...";

	setFetchAllProgress(0, 0);
	setFetchAllLog("Waiting for server progress...", "");

	ui.fetchAllCancelButton.classList.remove("hidden");
	ui.fetchAllCancelButton.disabled = false;
	ui.fetchAllCloseButton.disabled = true;
	ui.fetchAllOverlay.classList.add("active");
}

function closeFetchAllOverlay() {
	if (!ui.fetchAllOverlay) {
		return;
	}

	ui.fetchAllOverlay.classList.remove("active");
}

function setFetchAllSummary(text) {
	if (!ui.fetchAllSummary) {
		return;
	}

	ui.fetchAllSummary.textContent = text;
}

function setFetchAllProgress(index, total) {
	if (!ui.fetchAllProgressBar || !ui.fetchAllProgressText) {
		return;
	}

	if (!total || total < 1) {
		ui.fetchAllProgressBar.style.width = "0%";
		ui.fetchAllProgressText.textContent = "Preparing...";

		return;
	}

	const safeIndex = Math.max(0, Math.min(index, total)),
		percent = Math.round((safeIndex / total) * 100);

	ui.fetchAllProgressBar.style.width = `${percent}%`;
	ui.fetchAllProgressText.textContent = `${safeIndex}/${total} (${percent}%)`;
}

function setFetchAllLog(text, type = "") {
	if (!ui.fetchAllLog) {
		return;
	}

	ui.fetchAllLog.className = "fetch-all-log";

	if (type) {
		ui.fetchAllLog.classList.add(type);
	}

	ui.fetchAllLog.textContent = text;
}

function setFetchAllResult(status, summary, log) {
	if (!ui.fetchAllOverlay || !ui.fetchAllCloseButton || !ui.fetchAllCancelButton) {
		return;
	}

	ui.fetchAllOverlay.classList.remove("running", "ok", "error");
	ui.fetchAllOverlay.classList.add(status);

	setFetchAllSummary(summary);
	setFetchAllLog(log, status === "ok" ? "ok" : "error");

	ui.fetchAllCancelButton.classList.add("hidden");
	ui.fetchAllCloseButton.disabled = false;
}

function onFetchAllCancelClick() {
	if (!ui.fetchAllAbortController || !ui.fetchAllCancelButton) {
		return;
	}

	ui.fetchAllCancelButton.disabled = true;
	setFetchAllSummary("Canceling...");
	setFetchAllLog("Cancel requested. Waiting for backend to stop...");

	ui.fetchAllAbortController.abort();
}

async function streamNDJson(path, options, onMessage) {
	const headers = options.headers ? { ...options.headers } : {};

	if (state.token) {
		headers.Authorization = `Bearer ${state.token}`;
	}

	const response = await fetch(path, {
		...options,
		headers: headers,
	});

	if (!response.ok) {
		const text = await response.text();

		let payload = null;

		try {
			payload = JSON.parse(text);
		} catch {
			payload = null;
		}

		throw new Error(payload?.error || text || `Request failed (${response.status})`);
	}

	if (!response.body) {
		throw new Error("Streaming response not available.");
	}

	const reader = response.body.getReader(),
		decoder = new TextDecoder();

	let buffer = "";

	while (true) {
		const { value, done } = await reader.read();

		buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

		let newlineIndex = buffer.indexOf("\n");

		while (newlineIndex !== -1) {
			const line = buffer.slice(0, newlineIndex).trim();

			buffer = buffer.slice(newlineIndex + 1);

			if (line) {
				onMessage(JSON.parse(line));
			}

			newlineIndex = buffer.indexOf("\n");
		}

		if (done) {
			break;
		}
	}

	const tail = buffer.trim();

	if (tail) {
		onMessage(JSON.parse(tail));
	}
}

function isUiLocked() {
	return state.fetchingAllRecords;
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
	state.cloudflare = Boolean(info?.cloudflare);

	const zones = info?.zones;

	state.zones = zones && typeof zones === "object" && !Array.isArray(zones) ? zones : {};

	if (!state.authenticated) {
		state.activeZone = "";
		state.records = [];
		state.dyndnsUsers = [];

		return;
	}

	await loadDynDNSUsers();

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
		renderZones();
		setActiveZoneSelection(false);
		renderRecords();

		return;
	}

	if (state.loadingRecords && state.activeZone === zone) {
		return;
	}

	const zoneChanged = state.activeZone !== zone;

	state.activeZone = zone;

	setZoneHash(zone);

	state.records = [];

	setActiveZoneSelection(zoneChanged);

	state.loadingRecords = true;

	if (zoneChanged) {
		renderZones();
	} else {
		updateZoneSelectionAvailability();
	}

	renderRecords();

	try {
		const records = await api(`/-/${encodeURIComponent(zone)}`);

		state.records = Array.isArray(records) ? records : [];
	} catch (err) {
		state.records = [];

		setStatus(err.message, true);
	} finally {
		state.loadingRecords = false;

		updateZoneSelectionAvailability();
		renderRecords();

		setActiveZoneSelection(zoneChanged);
	}
}

async function refreshZoneFromCloudflare() {
	if (!state.activeZone) {
		return;
	}

	if (state.syncingRecords || state.loadingRecords || state.savingRecord) {
		return;
	}

	state.syncingRecords = true;

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
		state.syncingRecords = false;

		renderRecords();
	}
}

async function fetchAllZonesFromCloudflare() {
	if (state.fetchingAllRecords) {
		return;
	}

	state.fetchingAllRecords = true;

	renderHeader();
	renderZones();
	renderRecords();

	openFetchAllOverlay();

	setFetchAllLog("Started full zone sync.");

	const skippedZones = [];

	try {
		let lastIndex = 0,
			lastTotal = 0;

		ui.fetchAllAbortController = new AbortController();

		await streamNDJson("/-/records", { method: "PATCH", signal: ui.fetchAllAbortController.signal }, message => {
			if (message.status === "progress") {
				const index = Number(message.index) || 0,
					total = Number(message.total) || 0,
					label = `Zone ${index}/${total}: ${zoneDisplay(String(message.zone || ""))}`;

				lastIndex = index;
				lastTotal = total;

				setFetchAllSummary(label);
				setFetchAllLog(label);
				setFetchAllProgress(index, total);

				return;
			}

			if (message.status === "skipped") {
				const label = message.name || zoneDisplay(String(message.zone || "")),
					warning = `${label}: ${message.error || "Zone is no longer accessible in Cloudflare. Existing records have been kept."}`;

				skippedZones.push(warning);

				setFetchAllLog(warning, "error");

				return;
			}

			if (message.status === "done") {
				const finalTotal = lastTotal || lastIndex || 1;

				setFetchAllProgress(finalTotal, finalTotal);

				return;
			}

			if (message.status === "failed") {
				throw new Error(message.error || "Fetch-all sync failed.");
			}

			setFetchAllLog(JSON.stringify(message));
		});

		if (state.activeZone) {
			await loadZone(state.activeZone);
		}

		if (skippedZones.length) {
			const summary = `Sync completed with ${skippedZones.length} skipped zone${skippedZones.length === 1 ? "" : "s"}. Existing records have been kept.`;

			setFetchAllResult("error", summary, skippedZones.join("\n\n"));
			setStatus(summary, true);
		} else {
			setFetchAllResult("ok", "All zones synchronized.", "Completed successfully.");
			setStatus("All zones synchronized.", false);
		}
	} catch (err) {
		if (err?.name === "AbortError") {
			setFetchAllResult("error", "Fetch-all canceled.", "Request canceled by user.");
			setStatus("Fetch-all canceled.", false);
		} else {
			const details = [...skippedZones, err.message || "Sync failed."].join("\n\n");

			setFetchAllResult("error", "Fetch-all failed.", details);
			setStatus(err.message || "Sync failed.", true);
		}
	} finally {
		ui.fetchAllAbortController = null;
		state.fetchingAllRecords = false;

		renderHeader();
		renderZones();
		renderRecords();
	}
}

async function saveRecord(record, isUpdate) {
	if (state.savingRecord) {
		throw new Error("A record save is already in progress.");
	}

	state.savingRecord = true;

	renderRecords();

	try {
		await api(`/-/${encodeURIComponent(state.activeZone)}`, {
			method: isUpdate ? "PUT" : "POST",
			body: JSON.stringify(record),
		});

		setStatus(isUpdate ? "Record updated." : "Record created.", false);

		await loadZone(state.activeZone);
	} finally {
		state.savingRecord = false;

		renderRecords();
	}
}

async function deleteRecord(record) {
	if (state.deletingRecordId) {
		throw new Error("A record delete is already in progress.");
	}

	state.deletingRecordId = record.id;

	renderRecords();

	try {
		await api(`/-/${encodeURIComponent(state.activeZone)}/${encodeURIComponent(record.id)}`, {
			method: "DELETE",
		});

		setStatus(`Deleted ${record.name} (${record.type}).`, false);

		await loadZone(state.activeZone);
	} finally {
		state.deletingRecordId = "";

		renderRecords();
	}
}

async function loadDynDNSUsers() {
	if (state.loadingDynDNSUsers) {
		return;
	}

	state.loadingDynDNSUsers = true;

	renderDynDNS();

	try {
		const users = await api("/-/dyndns");

		state.dyndnsUsers = Array.isArray(users) ? users : [];
	} catch (err) {
		state.dyndnsUsers = [];

		setStatus(err.message, true);
	} finally {
		state.loadingDynDNSUsers = false;

		renderDynDNS();
	}
}

async function saveDynDNSUser(user, currentUsername) {
	if (state.savingDynDNSUser) {
		throw new Error("A DynDNS user save is already in progress.");
	}

	state.savingDynDNSUser = true;

	renderDynDNS();

	try {
		const path = currentUsername ? `/-/dyndns/${encodeURIComponent(currentUsername)}` : "/-/dyndns";

		await api(path, {
			method: currentUsername ? "PUT" : "POST",
			body: JSON.stringify(user),
		});

		setStatus(currentUsername ? "DynDNS user updated." : "DynDNS user created.", false);

		await loadDynDNSUsers();
	} finally {
		state.savingDynDNSUser = false;

		renderDynDNS();
	}
}

async function deleteDynDNSUser(user) {
	if (state.deletingDynDNSUsername) {
		throw new Error("A DynDNS user delete is already in progress.");
	}

	state.deletingDynDNSUsername = user.username;

	renderDynDNS();

	try {
		await api(`/-/dyndns/${encodeURIComponent(user.username)}`, { method: "DELETE" });

		setStatus(`Deleted DynDNS user ${user.username}.`, false);

		await loadDynDNSUsers();
	} finally {
		state.deletingDynDNSUsername = "";

		renderDynDNS();
	}
}

function confirmAction({ title, message, confirmText = "Confirm", cancelText = "Cancel", danger = false }) {
	return new Promise(resolve => {
		const overlay = make("div", "overlay"),
			modal = make("div", "modal", "confirm-modal"),
			top = make("div", "modal-top"),
			heading = make("h2", "modal-title"),
			text = make("p", "confirm-message"),
			footer = make("div", "modal-foot", "confirm-actions"),
			confirmButton = make("button", "ghost", danger ? "danger" : ""),
			cancelButton = make("button", "ghost");

		heading.textContent = title;
		text.textContent = message;

		confirmButton.type = "button";
		confirmButton.textContent = confirmText;

		cancelButton.type = "button";
		cancelButton.textContent = cancelText;

		const done = accepted => {
			document.removeEventListener("keydown", onKeydown);

			overlay.remove();

			resolve(accepted);
		};

		const onKeydown = event => {
			if (event.key === "Escape") {
				done(false);
			}
		};

		cancelButton.addEventListener("click", () => done(false));
		confirmButton.addEventListener("click", () => done(true));

		overlay.addEventListener("click", event => {
			if (event.target === overlay) {
				done(false);
			}
		});

		document.addEventListener("keydown", onKeydown);

		top.append(heading);

		footer.append(cancelButton, confirmButton);

		modal.append(top, text, footer);

		overlay.append(modal);

		document.body.append(overlay);
	});
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

	let content = "";

	if (mode === "raw") {
		content = String(formData.get("rawValue") || "").trim();
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

		content = config.build(fieldData).trim();
	}

	if (!content) {
		throw new Error("Record value cannot be empty.");
	}

	return {
		id: currentRecord?.id || randomId(),
		type: type,
		name: name,
		content: content,
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

function openZoneModal() {
	const overlay = make("div", "overlay"),
		modal = make("div", "modal"),
		form = make("form", "record-form"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		closeButton = make("button", "ghost"),
		nameField = make("label", "field"),
		nameTitle = make("span", "field-title"),
		nameInput = make("input", "input"),
		footer = make("div", "modal-foot"),
		cancelButton = make("button", "ghost"),
		submitButton = make("button", "button");

	title.textContent = "Create local zone";

	closeButton.type = "button";
	closeButton.textContent = "Close";

	nameTitle.textContent = "Zone name";

	nameInput.type = "text";
	nameInput.placeholder = "example.com";
	nameInput.required = true;
	nameInput.autofocus = true;

	cancelButton.type = "button";
	cancelButton.textContent = "Cancel";

	submitButton.type = "submit";
	submitButton.textContent = "Create";

	top.append(title, closeButton);
	nameField.append(nameTitle, nameInput);
	footer.append(cancelButton, submitButton);
	form.append(top, nameField, footer);
	modal.append(form);
	overlay.append(modal);

	document.body.append(overlay);

	nameInput.focus();

	const close = () => overlay.remove();

	closeButton.addEventListener("click", close);

	cancelButton.addEventListener("click", close);

	overlay.addEventListener("click", event => {
		if (event.target === overlay) {
			close();
		}
	});

	form.addEventListener("submit", async event => {
		event.preventDefault();

		submitButton.disabled = true;

		try {
			const zone = await api("/-/zones", { method: "POST", body: JSON.stringify({ name: nameInput.value.trim() }) });

			state.zones[zone.id] = zone.name;

			renderZones();

			await loadZone(zone.id);

			setStatus(`Created ${zone.name}.`, false);

			close();
		} catch (err) {
			setStatus(err.message, true);

			submitButton.disabled = false;
		}
	});
}

async function openDNSSECModal() {
	const zoneId = state.activeZone,
		zoneName = activeZoneName(),
		previousFocus = document.activeElement,
		overlay = make("div", "overlay"),
		modal = make("div", "modal"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		closeButton = make("button", "ghost"),
		content = make("div", "stack"),
		feedback = make("p", "field-hint");

	let details, busy = false;

	title.textContent = `DNSSEC — ${zoneName}`;
	title.id = "dnssec-modal-title";

	modal.setAttribute("role", "dialog");
	modal.setAttribute("aria-modal", "true");
	modal.setAttribute("aria-labelledby", title.id);

	feedback.setAttribute("role", "status");
	feedback.textContent = "Loading DNSSEC details...";

	closeButton.type = "button";
	closeButton.textContent = "Close";

	top.append(title, closeButton);
	modal.append(top, content, feedback);
	overlay.append(modal);

	document.body.append(overlay);

	closeButton.focus();

	const close = () => {
		if (busy) {
			return;
		}

		document.removeEventListener("keydown", onKeydown);

		overlay.remove();
		previousFocus?.focus();
	};
	const onKeydown = event => {
		if (event.key === "Escape") {
			close();
		}

		if (event.key !== "Tab") {
			return;
		}

		const controls = [...modal.querySelectorAll("button, input, select, textarea")].filter(control => !control.disabled),
			first = controls[0], last = controls[controls.length - 1];

		if (event.shiftKey && document.activeElement === first) {
			event.preventDefault();

			last?.focus();
		} else if (!event.shiftKey && document.activeElement === last) {
			event.preventDefault();

			first?.focus();
		}
	};

	document.addEventListener("keydown", onKeydown);
	closeButton.addEventListener("click", close);

	overlay.addEventListener("click", event => {
		if (event.target === overlay) {
			close();
		}
	});

	const showValue = (label, value, hint = "", multiline = false) => {
		if (value === undefined || value === null || value === "") {
			return;
		}

		const field = make("div", "field"),
			heading = make("span", "field-title"),
			row = make("div", "inline-row"),
			input = make(multiline ? "textarea" : "input", multiline ? "textarea" : "input", "mono", "dnssec-value"),
			copy = make("button", "ghost");

		heading.textContent = label;

		input.value = String(value);
		input.readOnly = true;
		input.setAttribute("aria-label", label);

		if (multiline) {
			input.rows = 4;
		} else {
			input.type = "text";
		}

		copy.type = "button";
		copy.textContent = "Copy";
		copy.setAttribute("aria-label", `Copy ${label}`);

		copy.addEventListener("click", async () => {
			try {
				await navigator.clipboard.writeText(input.value);

				feedback.textContent = `${label} copied.`;
			} catch {
				input.focus();
				input.select();

				feedback.textContent = `${label} selected. Use your browser's copy command.`;
			}
		});

		row.append(input, copy);
		field.append(heading, row);

		if (hint) {
			const description = make("span", "field-hint");

			description.textContent = hint;

			field.append(description);
		}

		content.append(field);
	};

	const render = () => {
		content.replaceChildren();

		const status = make("p", "field-title"),
			help = make("p", "field-hint"),
			providerField = make("label", "field"),
			providerLabel = make("span", "field-title"),
			provider = make("select", "input"),
			nameserverField = make("label", "field"),
			nameserverLabel = make("span", "field-title"),
			nameservers = make("textarea", "textarea"),
			removeField = make("label", "checkbox-field"),
			removed = make("input", "checkbox"),
			removeLabel = make("span", "field-hint"),
			footer = make("div", "modal-foot"),
			save = make("button", "button"),
			disable = make("button", "ghost", "danger");

		status.textContent = `${details.enabled ? "Enabled" : "Disabled"} · ${details.provider} · ${details.status}`;

		help.textContent = "Plat generates and retains a combined signing key and renews signatures automatically. For public validation, delegate your zone to nameservers serving plat on UDP and TCP port 53, then publish the DS below at your registrar. Signing does not automatically update your registrar or verify delegation.";

		providerLabel.textContent = "Signing provider";

		for (const [value, label] of [["plat", "Plat (recommended)"], ...(!zoneId.startsWith("local-") && state.cloudflare ? [["cloudflare", "Cloudflare"]] : [])]) {
			const option = make("option");

			option.value = value;
			option.textContent = label;

			provider.append(option);
		}

		provider.value = details.provider;
		provider.disabled = details.configured;

		providerField.append(providerLabel, provider);

		nameserverLabel.textContent = "Plat authoritative nameservers (one per line)";
		nameservers.rows = 3;
		nameservers.placeholder = "ns1.example.com\nns2.example.com";
		nameservers.value = (details.nameservers || []).join("\n");

		if (!nameservers.value && details.provider === "plat") {
			nameservers.value = state.records.filter(record => record.type === "NS" && record.name === "@").map(record => record.content).join("\n");
		}

		nameserverField.append(nameserverLabel, nameservers);

		const updateProvider = () => {
			nameserverField.hidden = provider.value !== "plat";
			help.textContent = provider.value === "cloudflare"
				? "Cloudflare generates the keys and signs the zone. Plat relays queries to Cloudflare's authoritative nameservers. Publish Cloudflare's DS at your registrar and keep the delegation pointed to Cloudflare. The API token needs Zone DNS Settings write access."
				: "Plat generates and retains a combined signing key and renews signatures automatically. For public validation, delegate your zone to nameservers serving plat on UDP and TCP port 53, then publish the DS below at your registrar. Signing does not automatically update your registrar or verify delegation.";
		};

		provider.addEventListener("change", async () => {
			if (busy) {
				return;
			}

			busy = true;

			closeButton.disabled = true;

			for (const control of content.querySelectorAll("button, input, select, textarea")) {
				control.disabled = true;
			}

			feedback.textContent = "Loading provider details...";

			try {
				details = await api(`/-/${zoneId}/dnssec?provider=${provider.value}`);

				feedback.textContent = "";
			} catch (err) {
				feedback.textContent = err.message;
			} finally {
				busy = false;

				closeButton.disabled = false;

				if (overlay.isConnected) {
					render();
				}
			}
		});

		updateProvider();

		content.append(status, help, providerField, nameserverField);

		if (details.ds_record) {
			showValue("DS Record", details.ds_record, "Publish this in the parent zone through your registrar, not as a record inside this zone.", true);
			showValue("Digest", details.digest);
			showValue("Digest Type", details.digest_type, details.digest_type === "2" ? "2 = SHA-256" : "");
			showValue("Algorithm", details.algorithm, details.algorithm === "15" ? "15 = Ed25519" : details.algorithm === "13" ? "13 = ECDSA P-256 / SHA-256" : "");
			showValue("Public Key", details.public_key, "", true);
			showValue("Key Tag", details.key_tag);
			showValue("Flags", details.flags, "257 = zone signing key + secure entry point (combined signing key). Cloudflare may use separate keys.");
			showValue("Protocol", details.protocol);
			showValue("DNSKEY Record", details.dnskey_record, "", true);
		}

		removed.type = "checkbox";

		removeLabel.textContent = "I removed the parent DS and waited for its cached copies to expire.";
		removeField.append(removed, removeLabel);
		removeField.hidden = !details.enabled;

		disable.type = "button";
		disable.textContent = "Disable DNSSEC";
		disable.hidden = !details.enabled;
		disable.disabled = true;

		removed.addEventListener("change", () => {
			disable.disabled = !removed.checked;
		});

		save.type = "button";
		save.textContent = details.enabled ? (details.provider === "cloudflare" ? "Use Cloudflare signing" : "Save nameservers") : "Enable DNSSEC";
		save.hidden = details.configured && details.provider === "cloudflare";

		const apply = async enabled => {
			if (busy) {
				return;
			}

			busy = true;

			closeButton.disabled = true;

			for (const control of content.querySelectorAll("button, input, select, textarea")) {
				control.disabled = true;
			}

			feedback.textContent = "Saving DNSSEC settings...";

			try {
				details = await api(`/-/${zoneId}/dnssec`, {
					method: "PUT",
					body: JSON.stringify({
						enabled: enabled,
						provider: provider.value,
						nameservers: nameservers.value.split(/[\s,]+/).filter(Boolean),
						parent_ds_removed: removed.checked,
					}),
				});

				feedback.textContent = enabled ? "DNSSEC signing enabled. Publish the DS at your registrar once delegation is ready." : "DNSSEC disabled. Plat retains its key for re-enabling.";
			} catch (err) {
				feedback.textContent = err.message;
			} finally {
				busy = false;

				closeButton.disabled = false;

				if (overlay.isConnected) {
					render();
				}
			}
		};

		save.addEventListener("click", () => apply(true));
		disable.addEventListener("click", () => apply(false));

		footer.append(disable, save);
		content.append(removeField, footer);
	};

	try {
		details = await api(`/-/${zoneId}/dnssec`);

		if (overlay.isConnected) {
			feedback.textContent = "";

			render();
		}
	} catch (err) {
		feedback.textContent = err.message;
	}
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
	rawInput.value = currentRecord?.content || "";

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

	typeHint.textContent = "Select a DNS record type.";

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

	const close = () => overlay.remove(),
		submitIdleText = currentRecord ? "Save" : "Create";

	let typedCache = parseRecordValue(typeInput.value, rawInput.value),
		submitting = false;

	const setSubmitting = value => {
		submitting = value;

		for (const field of form.querySelectorAll("input, select, textarea, button")) {
			field.disabled = value;
		}

		submitButton.textContent = value ? "Saving..." : submitIdleText;
	};

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

		if (submitting || state.savingRecord) {
			return;
		}

		try {
			if (modeSelect.value === "raw") {
				syncTypedFromRaw();
			} else {
				syncRawFromTyped();
			}

			const record = parseFormRecord(new FormData(form), currentRecord);

			setSubmitting(true);

			await saveRecord(record, Boolean(currentRecord));

			close();
		} catch (err) {
			setStatus(err.message, true);
			setSubmitting(false);
		}
	});

	renderTypeFields();
}

function openDynDNSUserModal(currentUser) {
	const overlay = make("div", "overlay"),
		modal = make("div", "modal"),
		form = make("form", "record-form"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		closeButton = make("button", "ghost"),
		usernameField = make("label", "field"),
		usernameTitle = make("span", "field-title"),
		usernameInput = make("input", "input"),
		passwordField = make("label", "field"),
		passwordTitle = make("span", "field-title"),
		passwordInput = make("input", "input"),
		passwordHint = make("span", "field-hint"),
		assignmentsTop = make("div", "inline-row"),
		assignmentsTitle = make("span", "field-title"),
		addAssignment = make("button", "ghost"),
		assignments = make("div", "dyndns-assignments"),
		footer = make("div", "modal-foot"),
		submitButton = make("button", "button"),
		cancelButton = make("button", "ghost");

	title.textContent = currentUser ? "Edit DynDNS user" : "Create DynDNS user";

	closeButton.type = "button";
	closeButton.textContent = "Close";

	usernameTitle.textContent = "Username";

	usernameInput.type = "text";
	usernameInput.name = "username";
	usernameInput.required = true;
	usernameInput.autocomplete = "off";
	usernameInput.value = currentUser?.username || "";

	usernameField.append(usernameTitle, usernameInput);

	passwordTitle.textContent = "Password";

	passwordInput.type = "password";
	passwordInput.name = "password";
	passwordInput.required = !currentUser;
	passwordInput.autocomplete = "new-password";

	passwordHint.textContent = currentUser ? "Leave blank to keep the current password." : "Stored securely as a one-way hash.";

	passwordField.append(passwordTitle, passwordInput, passwordHint);

	assignmentsTitle.textContent = "Assigned records";
	addAssignment.type = "button";
	addAssignment.textContent = "Add record";
	assignmentsTop.append(assignmentsTitle, addAssignment);

	submitButton.type = "submit";
	submitButton.textContent = currentUser ? "Save" : "Create";

	cancelButton.type = "button";
	cancelButton.textContent = "Cancel";

	footer.append(cancelButton, submitButton);
	top.append(title, closeButton);
	form.append(top, usernameField, passwordField, assignmentsTop, assignments, footer);
	modal.append(form);
	overlay.append(modal);

	document.body.append(overlay);

	const close = () => overlay.remove();

	const appendAssignment = (record = {}) => {
		const row = make("div", "dyndns-assignment"),
			zone = make("select", "input"),
			type = make("select", "input"),
			name = make("input", "input"),
			remove = make("button", "ghost", "danger");

		zone.name = "assignment-zone";
		zone.required = true;

		for (const [zoneId, zoneName] of zoneEntries()) {
			const option = make("option");

			option.value = zoneId;
			option.textContent = zoneDisplay(zoneName);

			zone.append(option);
		}

		zone.value = record.zone || state.activeZone || zoneEntries()[0]?.[0] || "";

		for (const recordType of ["A", "AAAA"]) {
			const option = make("option");

			option.value = recordType;
			option.textContent = recordType;

			type.append(option);
		}

		type.name = "assignment-type";
		type.value = record.type || "A";

		name.type = "text";
		name.name = "assignment-name";
		name.required = true;
		name.placeholder = "home or @";
		name.value = record.name || "";

		remove.type = "button";
		remove.textContent = "Remove";

		remove.addEventListener("click", () => row.remove());

		row.append(zone, type, name, remove);
		assignments.append(row);
	};

	for (const record of currentUser?.records || []) {
		appendAssignment(record);
	}

	addAssignment.addEventListener("click", () => appendAssignment());

	closeButton.addEventListener("click", close);

	cancelButton.addEventListener("click", close);

	overlay.addEventListener("click", event => {
		if (event.target === overlay) {
			close();
		}
	});

	form.addEventListener("submit", async event => {
		event.preventDefault();

		const records = Array.from(assignments.children, row => ({
			zone: row.querySelector('[name="assignment-zone"]').value,
			type: row.querySelector('[name="assignment-type"]').value,
			name: row.querySelector('[name="assignment-name"]').value.trim(),
		}));

		for (const field of form.querySelectorAll("input, select, button")) {
			field.disabled = true;
		}

		try {
			await saveDynDNSUser(
				{
					username: usernameInput.value.trim(),
					password: passwordInput.value,
					records: records,
				},
				currentUser?.username || ""
			);

			close();
		} catch (err) {
			setStatus(err.message, true);

			for (const field of form.querySelectorAll("input, select, button")) {
				field.disabled = false;
			}
		}
	});
}

function openDynDNSLogsModal(user) {
	const overlay = make("div", "overlay"),
		modal = make("div", "modal", "dyndns-log-modal"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		controls = make("div", "actions"),
		refresh = make("button", "ghost"),
		closeButton = make("button", "ghost"),
		note = make("p", "empty"),
		content = make("div");

	title.textContent = `DynDNS logs: ${user.username}`;
	refresh.type = "button";
	refresh.textContent = "Refresh";
	closeButton.type = "button";
	closeButton.textContent = "Close";
	note.textContent = "Most recent 50 authenticated update results. Times are shown in your local timezone.";

	const loadLogs = async () => {
		refresh.disabled = true;
		content.replaceChildren();

		const loading = make("p", "empty");

		loading.textContent = "Loading logs...";
		content.append(loading);

		try {
			const logs = await api(`/-/dyndns/${encodeURIComponent(user.username)}/logs`);

			if (!overlay.isConnected) {
				return;
			}

			if (!Array.isArray(logs) || !logs.length) {
				loading.textContent = "No updates logged yet.";

				return;
			}

			const tableWrap = make("div", "table-wrap"),
				table = make("table", "record-table", "dyndns-log-table"),
				head = make("thead"),
				headRow = make("tr"),
				body = make("tbody");

			for (const label of ["Time", "Hostname", "Address", "Source", "Result", "Details"]) {
				const cell = make("th");

				cell.textContent = label;
				headRow.append(cell);
			}

			for (let index = logs.length - 1; index >= 0; index--) {
				const entry = logs[index],
					row = make("tr"),
					time = new Date(entry.time);

				row.append(
					createCell(Number.isNaN(time.getTime()) ? entry.time : time.toLocaleString()),
					createCell(entry.hostname || "--", ["mono"]),
					createCell(entry.address || "--", ["mono"]),
					createCell(entry.source || "--", ["mono"]),
					createCell(entry.result),
					createCell(entry.error || "--")
				);

				body.append(row);
			}

			head.append(headRow);
			table.append(head, body);
			tableWrap.append(table);
			content.replaceChildren(tableWrap);
		} catch (err) {
			if (overlay.isConnected) {
				loading.textContent = err.message;
			}
		} finally {
			refresh.disabled = false;
		}
	};

	refresh.addEventListener("click", loadLogs);
	closeButton.addEventListener("click", () => overlay.remove());

	overlay.addEventListener("click", event => {
		if (event.target === overlay) {
			overlay.remove();
		}
	});

	controls.append(refresh, closeButton);
	top.append(title, controls);
	modal.append(top, note, content);
	overlay.append(modal);
	document.body.append(overlay);

	loadLogs();
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
		if (state.cloudflare) {
			const fetchAll = make("button", "ghost", "warn");

			fetchAll.type = "button";
			fetchAll.textContent = state.fetchingAllRecords ? "Syncing all..." : "Sync all";
			fetchAll.disabled = state.fetchingAllRecords;
			fetchAll.addEventListener("click", onFetchAllClick);

			controls.append(fetchAll);
		}

		const logout = make("button", "ghost", "danger");

		logout.type = "button";
		logout.textContent = "Log out";
		logout.addEventListener("click", onLogoutClick);

		controls.append(logout);
	}

	head.append(controls);

	return head;
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
	tokenInput.placeholder = "Access token";

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
		actions = make("div", "actions"),
		list = make("div", "zone-list");

	title.textContent = "Zones";

	const add = make("button", "ghost");

	add.type = "button";
	add.textContent = "New";
	add.disabled = isUiLocked();

	add.addEventListener("click", openZoneModal);

	actions.append(add);

	if (activeZoneIsLocal()) {
		const remove = make("button", "ghost", "danger");

		remove.type = "button";
		remove.textContent = "Delete";
		remove.disabled = isUiLocked();

		remove.addEventListener("click", onDeleteZoneClick);

		actions.append(remove);
	}

	if (state.cloudflare) {
		const refresh = make("button", "ghost");

		refresh.type = "button";
		refresh.textContent = state.reloadingZones ? "Reloading..." : "Sync";
		refresh.disabled = state.reloadingZones || isUiLocked();

		refresh.addEventListener("click", onReloadZonesClick);

		actions.append(refresh);
	}

	top.append(title, actions);

	panel.append(top, list);

	for (const [zoneId, zoneName] of zoneEntries()) {
		const button = make("button", "zone-item", zoneId === state.activeZone ? "active" : "");

		button.type = "button";
		button.disabled = zoneSelectionIsBusy();
		button.dataset.zoneId = zoneId;
		button.textContent = zoneDisplay(zoneName);
		button.title = `${zoneDisplay(zoneName)} (${zoneId})`;
		button.addEventListener("click", () => onZoneClick(zoneId));

		list.append(button);
	}

	return panel;
}

function zoneSelectionIsBusy() {
	return state.loadingRecords || state.syncingRecords || state.savingRecord || Boolean(state.deletingRecordId) || isUiLocked();
}

function updateZoneSelectionAvailability() {
	if (!ui.zonesSlot) {
		return;
	}

	const disabled = zoneSelectionIsBusy();

	for (const button of ui.zonesSlot.querySelectorAll(".zone-item")) {
		if (button.disabled !== disabled) {
			button.disabled = disabled;
		}
	}
}

function setActiveZoneSelection(ensureVisible = false) {
	if (!ui.zonesSlot) {
		return;
	}

	const current = ui.zonesSlot.querySelector(".zone-item.active"),
		next = ui.zonesSlot.querySelector(`.zone-item[data-zone-id="${state.activeZone}"]`);

	if (current && current !== next) {
		current.classList.remove("active");
	}

	if (next && !next.classList.contains("active")) {
		next.classList.add("active");
	}

	if (ensureVisible && next) {
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
		case "SSHFP":
			if (parts.length >= 2) {
				return `algo ${parts[0]} type ${parts[1]}`;
			}

			return "--";
		case "DS":
			if (parts.length >= 3) {
				return `tag ${parts[0]} algo ${parts[1]} digest ${parts[2]}`;
			}

			return "--";
		case "DNSKEY":
			if (parts.length >= 3) {
				return `flags ${parts[0]} proto ${parts[1]} algo ${parts[2]}`;
			}

			return "--";
		case "CERT":
			if (parts.length >= 3) {
				return `type ${parts[0]} tag ${parts[1]} algo ${parts[2]}`;
			}

			return "--";
		case "NAPTR":
			if (parts.length >= 2) {
				return `order ${parts[0]} pref ${parts[1]}`;
			}

			return "--";
		default:
			return "--";
	}
}

function hasEmailRecords() {
	const zoneName = zoneDisplay(activeZoneName()).toLowerCase();

	return state.records.some(record => {
		const type = record.type.toUpperCase(),
			fullName = record.name.toLowerCase().replace(/\.$/, ""),
			name = fullName.endsWith(`.${zoneName}`) ? fullName.slice(0, -zoneName.length - 1) : fullName,
			content = decodeTXT(record.content).trim().toLowerCase();

		return type === "MX" || type === "SPF"
			|| name === "_dmarc" || name.startsWith("_dmarc.")
			|| name === "_domainkey" || name.endsWith("._domainkey") || name.includes("._domainkey.")
			|| (type === "TXT" && /^(v=spf1|v=dkim1|v=dmarc1)/.test(content));
	});
}

function createEmailProtection() {
	const note = make("div", "note"),
		button = make("button", "email-protection-link");

	button.type = "button";
	button.textContent = "Protect unused email";

	button.addEventListener("click", openEmailProtectionModal);

	note.append(button);

	return note;
}

function openEmailProtectionModal() {
	const zoneID = state.activeZone,
		zoneName = zoneDisplay(activeZoneName()),
		previousFocus = document.activeElement,
		overlay = make("div", "overlay"),
		modal = make("div", "modal", "email-protection-modal"),
		form = make("form", "record-form"),
		top = make("div", "modal-top"),
		title = make("h2", "modal-title"),
		closeButton = make("button", "ghost"),
		help = make("p", "email-protection-help"),
		label = make("label", "field"),
		emailTitle = make("span", "field-title"),
		email = make("input", "input"),
		reportingHelp = make("span", "field-hint"),
		preview = make("div", "email-protection-preview"),
		feedback = make("p", "field-hint", "email-protection-feedback"),
		footer = make("div", "modal-foot"),
		cancel = make("button", "ghost"),
		submit = make("button", "button");

	let busy = false;

	title.textContent = `Email protection — ${zoneName}`;
	title.id = "email-protection-title";

	modal.setAttribute("role", "dialog");
	modal.setAttribute("aria-modal", "true");
	modal.setAttribute("aria-labelledby", title.id);
	modal.setAttribute("aria-describedby", "email-protection-help");

	closeButton.type = "button";
	closeButton.textContent = "Close";

	help.id = "email-protection-help";
	help.textContent = "For domains that do not send email. Add SPF, DKIM, and DMARC policies asking receiving mail servers to reject mail claiming to come from this domain or its subdomains. Change these records before setting up email. Existing email records are checked again before creation.";

	emailTitle.textContent = "Reporting email address (optional)";

	email.type = "email";
	email.name = "reporting_email";
	email.placeholder = "test@example.com";
	email.autocomplete = "email";
	email.setAttribute("aria-describedby", "email-protection-reporting-help");

	reportingHelp.id = "email-protection-reporting-help";
	reportingHelp.textContent = "Receive aggregate DMARC reports. An address on another domain may need authorization from that domain’s email provider.";

	feedback.setAttribute("role", "status");
	feedback.hidden = true;

	const recordPreview = (purpose, name, content) => {
		const card = make("section", "email-protection-record"),
			heading = make("div", "email-protection-record-head"),
			caption = make("h3"),
			type = make("span", "field-hint", "mono"),
			owner = make("div", "field"),
			ownerTitle = make("span", "field-title"),
			ownerValue = make("code"),
			value = make("div", "field"),
			valueTitle = make("span", "field-title"),
			valueContent = make("code", "email-protection-record-value");

		caption.textContent = purpose;

		type.textContent = "TXT";

		ownerTitle.textContent = "Name";

		ownerValue.textContent = name;

		valueTitle.textContent = "Value";

		valueContent.textContent = content;

		heading.append(caption, type);
		owner.append(ownerTitle, ownerValue);
		value.append(valueTitle, valueContent);
		card.append(heading, owner, value);
		preview.append(card);

		return valueContent;
	};

	recordPreview("SPF · Deny all senders", zoneName, "v=spf1 -all");
	recordPreview("DKIM · Revoke signing keys", "*._domainkey", "v=DKIM1; p=");

	const dmarcValue = recordPreview("DMARC · Reject spoofed mail", "_dmarc", "");

	const updatePreview = () => {
		const reportingEmail = email.value.trim(),
			reportingTag = reportingEmail ? ` rua=mailto:${reportingEmail};` : "";

		dmarcValue.textContent = `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;${reportingTag}`;
	};

	email.addEventListener("input", updatePreview);

	updatePreview();

	submit.type = "submit";
	submit.textContent = "Create protection records";

	cancel.type = "button";
	cancel.textContent = "Cancel";

	top.append(title, closeButton);
	label.append(emailTitle, email, reportingHelp);
	footer.append(cancel, submit);
	form.append(top, help, label, preview, feedback, footer);
	modal.append(form);
	overlay.append(modal);

	document.body.append(overlay);

	const close = () => {
		if (busy) {
			return;
		}

		document.removeEventListener("keydown", onKeydown);

		overlay.remove();

		if (previousFocus?.isConnected) {
			previousFocus.focus();
		} else {
			ui.recordsSlot?.querySelector("button:not(:disabled)")?.focus();
		}
	};

	const onKeydown = event => {
		if (event.key === "Escape") {
			close();
		}

		if (event.key !== "Tab") {
			return;
		}

		const controls = [...modal.querySelectorAll("button, input")].filter(control => !control.disabled),
			first = controls[0], last = controls[controls.length - 1];

		if (!first || (event.shiftKey && document.activeElement === first)) {
			event.preventDefault();

			last?.focus();
		} else if (!event.shiftKey && document.activeElement === last) {
			event.preventDefault();

			first.focus();
		}
	};

	document.addEventListener("keydown", onKeydown);
	closeButton.addEventListener("click", close);
	cancel.addEventListener("click", close);

	overlay.addEventListener("click", event => {
		if (event.target === overlay) {
			close();
		}
	});

	email.focus();

	form.addEventListener("submit", async event => {
		event.preventDefault();

		if (busy || state.savingRecord || isUiLocked()) {
			return;
		}

		const reportingEmail = email.value.trim();

		let created = false;

		busy = true;

		state.savingRecord = true;

		email.disabled = closeButton.disabled = cancel.disabled = submit.disabled = true;

		submit.textContent = "Creating...";

		feedback.hidden = true;

		renderRecords();

		try {
			await api(`/-/${encodeURIComponent(zoneID)}/email-protection`, {
				method: "POST",
				body: JSON.stringify({ reporting_email: reportingEmail }),
			});

			setStatus("Email protection records created.", false);

			created = true;
		} catch (err) {
			feedback.textContent = err.message;
			feedback.hidden = false;
		} finally {
			state.savingRecord = false;

			if (state.activeZone === zoneID) {
				await loadZone(zoneID);
			} else {
				updateZoneSelectionAvailability();

				renderRecords();
			}

			busy = false;

			email.disabled = closeButton.disabled = cancel.disabled = submit.disabled = false;

			submit.textContent = "Create protection records";

			if (created) {
				close();
			}
		}
	});
}

function createRecords() {
	const panel = make("section", "panel", "records"),
		top = make("div", "panel-head"),
		title = make("h2", "panel-title"),
		actions = make("div", "actions"),
		sync = make("button", "ghost"),
		dnssec = make("button", "ghost"),
		add = make("button", "button"),
		tableWrap = make("div", "table-wrap"),
		table = make("table", "record-table"),
		colgroup = make("colgroup"),
		head = make("thead"),
		body = make("tbody");

	const recordsBusy = state.loadingRecords || state.syncingRecords || state.savingRecord || Boolean(state.deletingRecordId) || isUiLocked();

	title.textContent = state.activeZone ? `${zoneDisplay(activeZoneName())} records` : "Records";

	sync.type = "button";
	sync.textContent = state.syncingRecords ? "Synchronizing..." : state.loadingRecords ? "Loading..." : "Sync from Cloudflare";

	add.type = "button";
	add.textContent = state.savingRecord ? "Saving..." : "New record";

	sync.disabled = !state.activeZone || recordsBusy;
	add.disabled = !state.activeZone || recordsBusy;

	sync.addEventListener("click", onSyncClick);

	dnssec.type = "button";
	dnssec.textContent = "DNSSEC";
	dnssec.disabled = !state.activeZone || recordsBusy;

	dnssec.addEventListener("click", openDNSSECModal);
	add.addEventListener("click", onNewRecordClick);

	if (state.cloudflare && !activeZoneIsLocal()) {
		actions.append(sync);
	}

	actions.append(dnssec, add);

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

		empty.textContent = state.loadingRecords ? "Loading records..." : state.syncingRecords ? "Synchronizing records..." : "No records in this zone yet.";

		panel.append(empty);

		if (!recordsBusy && !hasEmailRecords()) {
			panel.append(createEmailProtection());
		}

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
			createCell(record.content, ["value", "w-content"]),
			createCell(!record.ttl || record.ttl === 1 ? "auto" : `${record.ttl}s`, ["mono", "w-ttl"]),
			createCell(recordTags(record), ["w-tags"]),
			createCell(recordDetails(record), ["mono", "w-details"])
		);

		edit.type = "button";
		edit.textContent = "Edit";
		edit.disabled = recordsBusy;

		del.type = "button";
		del.textContent = state.deletingRecordId === record.id ? "Deleting..." : "Delete";
		del.disabled = recordsBusy;

		edit.addEventListener("click", () => onEditRecordClick(record));
		del.addEventListener("click", () => onDeleteRecordClick(record));

		controls.append(edit, del);

		row.append(controls);

		body.append(row);
	}

	tableWrap.append(table);

	panel.append(tableWrap);

	if (!recordsBusy && !hasEmailRecords()) {
		panel.append(createEmailProtection());
	}

	return panel;
}

function createDynDNS() {
	const panel = make("section", "panel", "dyndns"),
		top = make("div", "panel-head"),
		title = make("h2", "panel-title"),
		add = make("button", "button"),
		tableWrap = make("div", "table-wrap"),
		table = make("table", "record-table", "dyndns-table"),
		head = make("thead"),
		body = make("tbody");

	const busy = state.loadingDynDNSUsers || state.savingDynDNSUser || Boolean(state.deletingDynDNSUsername) || isUiLocked();

	title.textContent = "DynDNS";

	add.type = "button";
	add.textContent = state.savingDynDNSUser ? "Saving..." : "New user";
	add.disabled = busy;

	add.addEventListener("click", () => openDynDNSUserModal());

	top.append(title, add);
	panel.append(top);

	const headRow = make("tr");

	for (const label of ["Username", "Assigned A/AAAA records", "Actions"]) {
		const cell = make("th");

		cell.textContent = label;

		headRow.append(cell);
	}

	head.append(headRow);
	table.append(head, body);

	for (const user of state.dyndnsUsers) {
		const records = (Array.isArray(user.records) ? user.records : []).map(record => {
			const zoneName = state.zones[record.zone] || record.zone,
				name = record.name === "@" ? zoneName : `${record.name}.${zoneName}`;

			return `${record.type} ${zoneDisplay(name)}`;
		});

		const row = make("tr"),
			controls = make("td", "row-actions"),
			logs = make("button", "ghost"),
			edit = make("button", "ghost"),
			remove = make("button", "ghost", "danger");

		logs.type = "button";
		logs.textContent = "Logs";
		logs.addEventListener("click", () => openDynDNSLogsModal(user));

		edit.type = "button";
		edit.textContent = "Edit";
		edit.disabled = busy;

		edit.addEventListener("click", () => openDynDNSUserModal(user));

		remove.type = "button";
		remove.textContent = state.deletingDynDNSUsername === user.username ? "Deleting..." : "Delete";
		remove.disabled = busy;

		remove.addEventListener("click", async () => {
			const confirmed = await confirmAction({
				title: "Delete DynDNS user",
				message: `Delete ${user.username}? Assigned DNS records will not be removed.`,
				confirmText: "Delete",
				danger: true,
			});

			if (!confirmed) {
				return;
			}

			try {
				await deleteDynDNSUser(user);
			} catch (err) {
				setStatus(err.message, true);
			}
		});

		controls.append(logs, edit, remove);

		row.append(createCell(user.username, ["mono"]), createCell(records.join(", ") || "--", ["mono"]), controls);

		body.append(row);
	}

	if (state.dyndnsUsers.length) {
		tableWrap.append(table);
		panel.append(tableWrap);
	} else {
		const empty = make("p", "empty");

		empty.textContent = state.loadingDynDNSUsers ? "Loading DynDNS users..." : "No DynDNS users yet.";

		panel.append(empty);
	}

	return panel;
}

function mountShell() {
	if (ui.mounted) {
		return;
	}

	const shell = make("main", "shell");

	ui.headerSlot = make("div", "header-slot");
	ui.contentSlot = make("div", "content-slot");

	shell.append(ui.headerSlot, ui.contentSlot);

	app.append(shell);

	ui.mounted = true;
}

function clearAuthedSlots() {
	ui.zonesSlot = null;
	ui.workspaceSlot = null;
	ui.workspaceTabs = null;
	ui.recordsSlot = null;
	ui.dyndnsSlot = null;
	ui.recordsScrollByZone = {};
}

function ensureAuthedLayout() {
	if (ui.zonesSlot && ui.workspaceSlot && ui.workspaceTabs && ui.recordsSlot && ui.dyndnsSlot) {
		return;
	}

	const layout = make("div", "layout"),
		workspace = make("div", "workspace"),
		tabs = make("div", "workspace-tabs");

	ui.zonesSlot = make("div", "zones-slot");
	ui.workspaceSlot = workspace;
	ui.workspaceTabs = tabs;
	ui.recordsSlot = make("div", "records-slot");
	ui.dyndnsSlot = make("div", "dyndns-slot");

	const tabList = [
		["records", "Records"],
		["dyndns", "DynDNS"],
	];

	for (const [workspaceName, label] of tabList) {
		const tab = make("button", "workspace-tab");

		tab.type = "button";
		tab.dataset.workspace = workspaceName;
		tab.textContent = label;
		tab.setAttribute("role", "tab");

		tab.addEventListener("click", () => {
			state.activeWorkspace = workspaceName;
			syncWorkspaceTabs();
		});

		tabs.append(tab);
	}

	tabs.setAttribute("role", "tablist");
	tabs.setAttribute("aria-label", "DNS management");

	workspace.append(tabs, ui.recordsSlot, ui.dyndnsSlot);
	layout.append(ui.zonesSlot, workspace);

	ui.contentSlot.replaceChildren(layout);

	syncWorkspaceTabs();
}

function syncWorkspaceTabs() {
	if (!ui.workspaceTabs || !ui.recordsSlot || !ui.dyndnsSlot) {
		return;
	}

	for (const tab of ui.workspaceTabs.children) {
		const active = tab.dataset.workspace === state.activeWorkspace;

		tab.classList.toggle("active", active);

		tab.setAttribute("aria-selected", String(active));
	}

	ui.recordsSlot.classList.toggle("hidden", state.activeWorkspace !== "records");
	ui.dyndnsSlot.classList.toggle("hidden", state.activeWorkspace !== "dyndns");
}

function renderHeader() {
	if (!ui.mounted) {
		return;
	}

	ui.headerSlot.replaceChildren(createHeader());
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

function renderDynDNS() {
	if (!ui.mounted || !state.authenticated) {
		return;
	}

	ensureAuthedLayout();

	ui.dyndnsSlot.replaceChildren(createDynDNS());
}

function renderAuthedPanels() {
	renderZones();
	renderRecords();
	renderDynDNS();
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
	if (isUiLocked()) {
		return;
	}

	state.theme = state.theme === "dark" ? "light" : "dark";

	applyTheme();
}

function onLogoutClick() {
	state.token = "";
	state.authenticated = false;
	state.cloudflare = false;
	state.zones = {};
	state.activeZone = "";
	state.records = [];
	state.loadingRecords = false;
	state.syncingRecords = false;
	state.savingRecord = false;
	state.deletingRecordId = "";
	state.reloadingZones = false;
	state.fetchingAllRecords = false;
	state.dyndnsUsers = [];
	state.loadingDynDNSUsers = false;
	state.savingDynDNSUser = false;
	state.deletingDynDNSUsername = "";
	state.activeWorkspace = "records";

	sessionStorage.removeItem("plat-token");
	clearNotifications();

	if (ui.fetchAllAbortController) {
		ui.fetchAllAbortController.abort();
	}

	closeFetchAllOverlay();

	setZoneHash("");

	render();
}

async function onReloadZonesClick() {
	if (isUiLocked()) {
		return;
	}

	if (state.reloadingZones) {
		return;
	}

	state.reloadingZones = true;

	renderZones();

	try {
		const zones = await api("/-/zones", { method: "PATCH" });

		state.zones = zones && typeof zones === "object" && !Array.isArray(zones) ? zones : {};

		if (!Object.keys(state.zones).length) {
			state.activeZone = "";
			state.records = [];

			setZoneHash("");
		} else if (!state.activeZone || !state.zones[state.activeZone]) {
			const hashZone = zoneFromHash();

			if (hashZone && state.zones[hashZone]) {
				state.activeZone = hashZone;
			} else {
				state.activeZone = zoneEntries()[0][0];
			}

			state.records = [];

			setZoneHash(state.activeZone);
		}

		renderZones();

		setStatus("Zone list updated.", false);
	} catch (err) {
		setStatus(err.message, true);
	} finally {
		state.reloadingZones = false;

		renderZones();
	}
}

async function onZoneClick(zone) {
	if (isUiLocked()) {
		return;
	}

	await loadZone(zone);
}

async function onDeleteZoneClick() {
	if (!activeZoneIsLocal() || isUiLocked()) {
		return;
	}

	const zoneId = state.activeZone,
		zoneName = activeZoneName();

	const confirmed = await confirmAction({
		title: "Delete local zone",
		message: `Delete ${zoneName} and all its records? This cannot be undone.`,
		confirmText: "Delete",
		danger: true,
	});

	if (!confirmed) {
		return;
	}

	try {
		await api(`/-/zones/${encodeURIComponent(zoneId)}`, { method: "DELETE" });

		delete state.zones[zoneId];

		state.activeZone = zoneEntries()[0]?.[0] || "";

		setZoneHash(state.activeZone);

		renderZones();

		await loadZone(state.activeZone);

		setStatus(`Deleted ${zoneName}.`, false);
	} catch (err) {
		setStatus(err.message, true);
	}
}

async function onHashChange() {
	if (!state.authenticated || isUiLocked()) {
		return;
	}

	const hashZone = zoneFromHash();
	if (!hashZone || hashZone === state.activeZone || !state.zones[hashZone]) {
		return;
	}

	await loadZone(hashZone);
}

async function onSyncClick() {
	if (isUiLocked()) {
		return;
	}

	await refreshZoneFromCloudflare();
}

function onNewRecordClick() {
	if (isUiLocked()) {
		return;
	}

	openRecordModal();
}

function onEditRecordClick(record) {
	if (isUiLocked()) {
		return;
	}

	openRecordModal(record);
}

async function onDeleteRecordClick(record) {
	if (isUiLocked()) {
		return;
	}

	if (state.deletingRecordId) {
		return;
	}

	const okayDelete = await confirmAction({
		title: "Delete record",
		message: `Delete ${record.name} (${record.type})? This cannot be undone.`,
		confirmText: "Delete",
		danger: true,
	});

	if (!okayDelete) {
		return;
	}

	try {
		await deleteRecord(record);
	} catch (err) {
		setStatus(err.message, true);
	}
}

async function onFetchAllClick() {
	if (isUiLocked()) {
		return;
	}

	await fetchAllZonesFromCloudflare();
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
