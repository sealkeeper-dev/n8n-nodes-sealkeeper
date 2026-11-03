// Reading trust from SealKeeper and verifying the SEAL in the answer. The
// requests go through n8n's request helper, every answer is read in
// protocol.ts and every SEAL in seal.ts.

import type { IHttpRequestOptions } from 'n8n-workflow';

import {
	ANSWER_MAX_BYTES,
	KEYS_URL,
	KeyCache,
	MCP_URL,
	SealKeeperError,
	TIMEOUT_SECONDS,
	UnavailableError,
	keysHeaders,
	mcpHeaders,
	readAnswer,
	readKeysAnswer,
	retryWait,
	toolCall,
	trustTarget,
} from './protocol';
import {
	type SealBrokenReason,
	type Verified,
	type VerifiedSeal,
	isAgentId,
	isObject,
	readKeys,
	sealKid,
	verifyWithKeys,
} from './seal';

export interface Answer {
	status: number;
	headers: Record<string, string>;
	body: Uint8Array;
}

export type Send = (
	method: 'GET' | 'POST',
	url: string,
	body: string | undefined,
	headers: Record<string, string>,
) => Promise<Answer>;

// What a lookup needs from outside. send moves the bytes, sleep waits
// before the one retry of a 429, now answers Unix seconds and decides
// whether a SEAL is current, and keys is the copy of the key document.
export interface Io {
	send: Send;
	sleep: (milliseconds: number) => Promise<void>;
	now: () => number;
	keys: KeyCache;
}

// What get_trust answered for a target, with its SEAL verified here.
//
// seal is the verified SEAL, set only when the SEAL checked out. Otherwise
// code says why there is none.
//
//   broken      the SEAL did not verify, broken is the reason
//   withheld    SealKeeper withholds the SEAL, reason is why, since when
//   no_seal     the agent has no SEAL, dormantDays how long it is quiet
//   checking    the agent is still being checked
//   delisted    the agent is no longer listed
//   not_found   the target names no agent
//   unknown     a shown answer with no SEAL that says nothing more
//
// A code or a status this version does not know is passed through as it
// came, with the whole answer in raw. handle is the agent's handle as the
// answer gives it, unsigned and for display only. Level, kind and Trust
// Score are only ever read from seal.
export interface Lookup {
	status: string;
	seal: VerifiedSeal | null;
	code: string | null;
	broken: SealBrokenReason | null;
	reason: string | null;
	since: string | null;
	dormantDays: number | null;
	handle: string | null;
	raw: Record<string, unknown> | null;
}

type Data = Record<string, unknown>;

const text = (value: unknown): string | null => (typeof value === 'string' ? value : null);

const NO_SEAL: Omit<Lookup, 'status'> = {
	seal: null,
	code: null,
	broken: null,
	reason: null,
	since: null,
	dormantDays: null,
	handle: null,
	raw: null,
};

// The SEAL of a shown answer and the agent id to check it against. The id
// is the one the target named when it named one, else the answer's agent
// id. null when the answer carries no SEAL.
export function sealToCheck(answer: Data, namedId: string | null): [string, string] | null {
	const seal = answer.seal;
	if (answer.status !== 'shown' || seal === null || seal === undefined) return null;
	if (typeof seal !== 'string') {
		throw new SealKeeperError("SealKeeper's answer has a SEAL that is not a string");
	}
	const agentId = isObject(answer.agent) ? answer.agent.id : undefined;
	const expected = namedId ?? agentId;
	if (!isAgentId(expected)) {
		throw new SealKeeperError("SealKeeper's answer names no agent id for its SEAL");
	}
	return [seal, expected];
}

// The Lookup of a get_trust answer, given what its SEAL verified to.
export function lookupOf(answer: Data, verified: Verified | null): Lookup {
	const status = text(answer.status) ?? 'unknown';
	const handle = isObject(answer.agent) ? text(answer.agent.handle) : null;
	const base = { ...NO_SEAL, status, handle };
	if (verified !== null && 'seal' in verified) return { ...base, seal: verified.seal };
	if (verified !== null) return { ...base, code: 'broken', broken: verified.broken };
	if (status === 'checking' || status === 'delisted' || status === 'not_found') {
		return { ...base, code: status };
	}
	if (status !== 'shown') return { ...base, code: 'unknown', raw: answer };
	const withheld = answer.withheld;
	if (!isObject(withheld) || typeof withheld.code !== 'string') {
		return { ...base, code: 'unknown', raw: answer };
	}
	const code = withheld.code;
	if (code === 'withheld') {
		return { ...base, code, reason: text(withheld.reason), since: text(withheld.since) };
	}
	if (code === 'no_seal') {
		const days = withheld.dormant_days;
		const whole = typeof days === 'number' && Number.isSafeInteger(days) && days >= 0;
		return { ...base, code, dormantDays: whole ? days : null };
	}
	if (code === 'checking') return { ...base, code };
	return { ...base, code, raw: answer };
}

async function call(io: Io, name: string, args: Data): Promise<Data> {
	const body = toolCall(name, args);
	for (let attempt = 0; ; attempt++) {
		const answer = await io.send('POST', MCP_URL, body, mcpHeaders());
		const wait = retryWait(answer.status, answer.headers, attempt);
		if (wait === null) return readAnswer(answer.status, answer.body);
		await io.sleep(wait * 1000);
	}
}

// Verifies a SEAL here, against SealKeeper's published keys, for the agent
// id expected. Throws UnavailableError when the keys cannot be had and no
// copy younger than five minutes knows the kid.
export async function verify(io: Io, seal: string, expected: string): Promise<Verified> {
	const now = io.now();
	const kid = sealKid(seal);
	if (kid === null) return { broken: 'malformed' };
	let keys = io.keys.usable(kid, now);
	if (keys === null) {
		const answer = await io.send('GET', KEYS_URL, undefined, keysHeaders());
		const fresh = readKeys(readKeysAnswer(answer.status, answer.body));
		if (fresh === null) {
			throw new UnavailableError('could not use the SealKeeper keys, they hold no Ed25519 key');
		}
		io.keys.store(fresh, now);
		keys = fresh;
	}
	return verifyWithKeys(seal, keys, now, expected);
}

// get_trust for target, with the SEAL in its answer verified here.
export async function lookUp(io: Io, target: string): Promise<Lookup> {
	const [argument, namedId] = trustTarget(target);
	const answer = await call(io, 'get_trust', { agent: argument });
	const check = sealToCheck(answer, namedId);
	if (check === null) return lookupOf(answer, null);
	return lookupOf(answer, await verify(io, check[0], check[1]));
}

const TIMED_OUT = new Set(['ECONNABORTED', 'ETIMEDOUT', 'ERR_CANCELED']);

// The error a request that threw stands for. A body past the cap is
// SealKeeperError, a timeout or anything else that stopped the request is
// UnavailableError.
export function transportFailure(error: unknown): SealKeeperError {
	const code = isObject(error) && typeof error.code === 'string' ? error.code : '';
	const name = error instanceof Error ? error.name : 'Error';
	if (code === 'ERR_RESPONSE_TOO_LARGE') {
		return new SealKeeperError(`SealKeeper's answer is larger than ${ANSWER_MAX_BYTES} bytes`);
	}
	if (TIMED_OUT.has(code) || name === 'TimeoutError' || name === 'AbortError') {
		return new UnavailableError(`SealKeeper did not answer within ${TIMEOUT_SECONDS} seconds`);
	}
	return new UnavailableError(`could not reach SealKeeper, ${name}`);
}

function headersOf(value: unknown): Record<string, string> {
	const headers: Record<string, string> = {};
	if (!isObject(value)) return headers;
	for (const [name, item] of Object.entries(value)) {
		if (typeof item === 'string') headers[name.toLowerCase()] = item;
		else if (Array.isArray(item)) headers[name.toLowerCase()] = item.join(', ');
		else if (typeof item === 'number') headers[name.toLowerCase()] = String(item);
	}
	return headers;
}

function bytesOf(body: unknown): Uint8Array {
	if (body instanceof Uint8Array) return body;
	if (body instanceof ArrayBuffer) return new Uint8Array(body);
	if (typeof body === 'string') return Buffer.from(body, 'utf8');
	if (body === undefined || body === null) return new Uint8Array(0);
	throw new SealKeeperError("SealKeeper's answer is not bytes");
}

// The full answer n8n's request helper gives, as an Answer. A body past the
// cap is refused here too, for a helper that does not cap it.
export function answerOf(response: unknown): Answer {
	if (!isObject(response) || typeof response.statusCode !== 'number') {
		throw new SealKeeperError("SealKeeper's answer has no status");
	}
	const body = bytesOf(response.body);
	if (body.length > ANSWER_MAX_BYTES) {
		throw new SealKeeperError(`SealKeeper's answer is larger than ${ANSWER_MAX_BYTES} bytes`);
	}
	return { status: response.statusCode, headers: headersOf(response.headers), body };
}

export type HttpRequest = (options: IHttpRequestOptions) => Promise<unknown>;

// A Send through n8n's request helper. One request, no redirect followed,
// every status answered as it came, the body as bytes, capped and given up
// after the timeout.
export function sendWith(httpRequest: HttpRequest): Send {
	return async (method, url, body, headers) => {
		const options: IHttpRequestOptions = {
			method,
			url,
			headers,
			timeout: TIMEOUT_SECONDS * 1000,
			abortSignal: AbortSignal.timeout(TIMEOUT_SECONDS * 1000),
			disableFollowRedirect: true,
			ignoreHttpStatusErrors: true,
			returnFullResponse: true,
			encoding: 'arraybuffer',
			json: false,
			maxResponseBodyBytes: ANSWER_MAX_BYTES,
		};
		if (body !== undefined) options.body = body;
		let response: unknown;
		let failure: SealKeeperError | null = null;
		try {
			response = await httpRequest(options);
		} catch (error) {
			failure = transportFailure(error);
		}
		if (failure !== null) throw failure;
		return answerOf(response);
	};
}
