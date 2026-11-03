// The requests the node sends and how it reads the answers. Pure functions
// and one small key cache. The client only moves bytes, so every answer is
// read here.

import { DID_KEY_PREFIX, agentIdFromDidKey, isAgentId, isObject } from './seal';
import { VERSION } from './version';

export const MCP_URL = 'https://api.sealkeeper.run/mcp';
export const KEYS_URL = 'https://sealkeeper.run/.well-known/seal.json';
const PAGE_HOST = 'sealkeeper.run';
const API_HOST = 'api.sealkeeper.run';
export const MCP_PROTOCOL_VERSION = '2025-11-25';

export const TIMEOUT_SECONDS = 5;
export const ANSWER_MAX_BYTES = 64 * 1024;
// How long a copy of the keys is used before it is fetched again.
export const KEYS_MAX_AGE_SECONDS = 300;

// The longest line of server text an error carries.
const TEXT_MAX_CHARS = 500;
const PAGE_PATH = /^\/agents\/([^/]+)(?:\/([^/]+))?\/?$/;
const API_CARD_PATH = /^\/v1\/agents\/([A-Za-z0-9_-]{43})\/card\/?$/;
const URL_PARTS = /^([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/?#]*)([\s\S]*)$/;
const HTTP_URL = /^https?:\/\//i;

// SealKeeper answered something this node cannot use.
export class SealKeeperError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'SealKeeperError';
	}
}

// SealKeeper refused the target or the input, with its line saying why.
export class BadTargetError extends SealKeeperError {
	constructor(message: string) {
		super(message);
		this.name = 'BadTargetError';
	}
}

// SealKeeper could not be reached, timed out or asked to slow down.
export class UnavailableError extends SealKeeperError {
	constructor(message: string) {
		super(message);
		this.name = 'UnavailableError';
	}
}

export const USER_AGENT = `n8n-nodes-sealkeeper/${VERSION}`;

export const mcpHeaders = (): Record<string, string> => ({
	'content-type': 'application/json',
	accept: 'application/json, text/event-stream',
	'mcp-protocol-version': MCP_PROTOCOL_VERSION,
	'user-agent': USER_AGENT,
});

export const keysHeaders = (): Record<string, string> => ({
	accept: 'application/json',
	'user-agent': USER_AGENT,
});

// One stateless JSON-RPC tools/call, the whole request body.
export const toolCall = (name: string, args: Record<string, unknown>): string =>
	JSON.stringify({
		jsonrpc: '2.0',
		id: 1,
		method: 'tools/call',
		params: { name, arguments: args },
	});

// The seconds to wait before the one retry of a 429, else null. Only the
// first answer is retried, and only when Retry-After names whole seconds no
// longer than the timeout.
export function retryWait(
	status: number,
	headers: Record<string, string>,
	attempt: number,
): number | null {
	if (status !== 429 || attempt > 0) return null;
	const value = (headers['retry-after'] ?? '').trim();
	if (!/^[0-9]+$/.test(value)) return null;
	const seconds = Number(value);
	return seconds <= TIMEOUT_SECONDS ? seconds : null;
}

const short = (text: string): string =>
	text.length <= TEXT_MAX_CHARS ? text : `${text.slice(0, TEXT_MAX_CHARS)}...`;

const decoder = new TextDecoder('utf-8', { fatal: true });

function json(body: Uint8Array): unknown {
	try {
		return JSON.parse(decoder.decode(body));
	} catch {
		return undefined;
	}
}

function errorMessage(parsed: unknown): string {
	const error = isObject(parsed) ? parsed.error : undefined;
	const message = isObject(error) ? error.message : undefined;
	return typeof message === 'string' ? short(message) : 'no message';
}

function firstText(result: Record<string, unknown>): string {
	const content = result.content;
	if (Array.isArray(content)) {
		for (const item of content) {
			if (isObject(item) && typeof item.text === 'string') return short(item.text);
		}
	}
	return 'SealKeeper refused the input';
}

// The structuredContent of a tools/call answer, or the error it is. A 429
// or a 5xx is UnavailableError. A tool error is BadTargetError with the
// server's line. Any other status, a JSON-RPC error or an answer that is
// not a tool result is SealKeeperError.
export function readAnswer(status: number, body: Uint8Array): Record<string, unknown> {
	if (status === 429) throw new UnavailableError('SealKeeper is rate limiting this caller');
	if (status >= 500) throw new UnavailableError(`SealKeeper answered HTTP ${status}`);
	const parsed = json(body);
	if (status !== 200) {
		throw new SealKeeperError(
			`SealKeeper refused the request, HTTP ${status}: ${errorMessage(parsed)}`,
		);
	}
	if (!isObject(parsed)) throw new SealKeeperError("SealKeeper's answer is not a JSON object");
	if ('error' in parsed) {
		throw new SealKeeperError(`SealKeeper answered an error: ${errorMessage(parsed)}`);
	}
	const result = parsed.result;
	if (!isObject(result)) throw new SealKeeperError("SealKeeper's answer has no result");
	if (result.isError === true) throw new BadTargetError(firstText(result));
	const data = result.structuredContent;
	if (!isObject(data)) throw new SealKeeperError("SealKeeper's answer has no structuredContent");
	return data;
}

// The key document of a 200 answer. Anything else is UnavailableError.
export function readKeysAnswer(status: number, body: Uint8Array): unknown {
	if (status !== 200) {
		throw new UnavailableError(`could not load the SealKeeper keys, HTTP ${status}`);
	}
	const parsed = json(body);
	if (parsed === undefined) throw new UnavailableError('the SealKeeper key document is not JSON');
	return parsed;
}

export const pageUrl = (agentId: string): string => `https://sealkeeper.run/agents/${agentId}`;

function decoded(segment: string): string {
	try {
		return decodeURIComponent(segment);
	} catch {
		return segment;
	}
}

// Whether target is a SealKeeper page or API card URL, and its agent id. A
// page is /agents/<first>/<name> or /agents/<id> on sealkeeper.run, a card
// /v1/agents/<id>/card on api.sealkeeper.run. Only the id forms name an id.
export function ownUrlId(target: string): [boolean, string | null] {
	if (!HTTP_URL.test(target)) return [false, null];
	let url: URL;
	try {
		url = new URL(target);
	} catch {
		return [false, null];
	}
	if (url.protocol !== 'https:' || url.port !== '') return [false, null];
	if (url.hostname === PAGE_HOST) {
		const page = PAGE_PATH.exec(url.pathname);
		if (page === null) return [false, null];
		const first = decoded(page[1]);
		return [true, page[2] === undefined && isAgentId(first) ? first : null];
	}
	if (url.hostname === API_HOST) {
		const card = API_CARD_PATH.exec(url.pathname);
		if (card === null) return [false, null];
		return [true, isAgentId(card[1]) ? card[1] : null];
	}
	return [false, null];
}

// What get_trust is sent for target, and the agent id target names. A bare
// agent id goes as its page URL, and a did:key as the page URL of the id it
// names. Every other target goes as given.
export function trustTarget(target: unknown): [string, string | null] {
	if (typeof target !== 'string' || target.trim() === '') {
		throw new BadTargetError('the target must be a non-empty string');
	}
	const text = target.trim();
	if (text.startsWith(DID_KEY_PREFIX)) {
		const agentId = agentIdFromDidKey(text);
		if (agentId === null) throw new BadTargetError('the target is not an Ed25519 did:key');
		return [pageUrl(agentId), agentId];
	}
	if (isAgentId(text)) return [pageUrl(text), text];
	return [target, ownUrlId(text)[1]];
}

export const isHttpUrl = (target: string): boolean => HTTP_URL.test(target.trim());

// Whether target is an http or https URL other than SealKeeper's own.
export const isListedUrl = (target: string): boolean =>
	isHttpUrl(target) && !ownUrlId(target.trim())[0];

// url with only its host in lower case, and an empty path read as /.
export function hostLowered(url: string): string {
	const match = URL_PARTS.exec(url.trim());
	if (match === null) return url;
	const [, scheme, authority, rest] = match;
	const at = authority.lastIndexOf('@');
	const userinfo = at === -1 ? '' : authority.slice(0, at + 1);
	const host = authority.slice(at + 1);
	return `${scheme}${userinfo}${host.toLowerCase()}${rest === '' ? '/' : rest}`;
}

// The last key document fetched, kid to x, and when it was fetched.
export class KeyCache {
	private keys = new Map<string, string>();
	private fetchedAt: number | null = null;

	// The keys while the copy is younger than five minutes and knows kid. A
	// copy dated after now counts as too old.
	usable(kid: string, now: number): ReadonlyMap<string, string> | null {
		if (this.fetchedAt === null || !this.keys.has(kid)) return null;
		const age = now - this.fetchedAt;
		return age >= 0 && age < KEYS_MAX_AGE_SECONDS ? this.keys : null;
	}

	store(keys: Map<string, string>, now: number): void {
		this.keys = keys;
		this.fetchedAt = now;
	}
}
