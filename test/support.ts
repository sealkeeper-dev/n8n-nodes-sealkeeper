// Test data and a recorded SealKeeper served through a fake of n8n's
// request helper. No test reaches the network unless the live flag is set.

import { createPrivateKey, sign as edSign } from 'node:crypto';
import type { IHttpRequestOptions } from 'n8n-workflow';

import { type Io, sendWith } from '../nodes/SealKeeper/client';
import { KEYS_URL, KeyCache, MCP_URL } from '../nodes/SealKeeper/protocol';
import FIXTURE_AGENT from './fixtures/agent.json';
import INDEX from './fixtures/index.json';
import FIXTURE_KEYS from './fixtures/keys.json';

export { FIXTURE_AGENT, FIXTURE_KEYS, INDEX, KEYS_URL, MCP_URL };

const SEALS = import.meta.glob('./fixtures/seals/*.txt', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

const RECORDED = import.meta.glob('./recorded/*.json', {
	import: 'default',
	eager: true,
}) as Record<string, Recorded>;

interface Recorded {
	status: number;
	headers: Record<string, string>;
	body: unknown;
}

export const PINNED = INDEX.clocks.pinnedSeconds;
export const NOW_FROM = Date.parse(INDEX.clocks.nowFrom) / 1000;

export function sealFile(name: string): string {
	const text = SEALS[`./fixtures/seals/${name}.txt`];
	if (text === undefined) throw new Error(`no fixture ${name}`);
	return text;
}

export function recorded(name: string): Recorded {
	const record = RECORDED[`./recorded/${name}.json`];
	if (record === undefined) throw new Error(`no recording ${name}`);
	return record;
}

export const b64url = (raw: Uint8Array): string => Buffer.from(raw).toString('base64url');

export function payloadOf(seal: string): Record<string, unknown> {
	return JSON.parse(Buffer.from(seal.split('.')[1], 'base64url').toString('utf8'));
}

// The production answer for sealkeeper/test-agent, its SEAL and the keys
// document of the same day. The SEAL verifies at TEST_AGENT_CLOCK.
const shown = recorded('get-trust-shown').body as {
	result: { structuredContent: { seal: string; agent: { id: string } } };
};
export const TEST_AGENT_SEAL = shown.result.structuredContent.seal;
export const TEST_AGENT_ID = shown.result.structuredContent.agent.id;
export const TEST_AGENT_CLOCK = (payloadOf(TEST_AGENT_SEAL).iat as number) + 3600;
export const PRODUCTION_KEYS = recorded('keys-production').body;

// A test signing key, fixed so every SEAL it signs is the same bytes. The
// seed is the bytes 0 to 31.
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const TEST_KEY = createPrivateKey({
	key: Buffer.concat([PKCS8_ED25519, Buffer.from([...Array(32).keys()])]),
	format: 'der',
	type: 'pkcs8',
});
export const TEST_KID = 'test-1';
export const TEST_X = TEST_KEY.export({ format: 'jwk' }).x as string;
export const TEST_KEYS = new Map([[TEST_KID, TEST_X]]);

// A compact JWS of payload signed with the test key, header as given.
export function sign(payload: unknown, kid = TEST_KID, header?: unknown): string {
	const head = header ?? { alg: 'EdDSA', kid };
	const body = payload instanceof Uint8Array ? payload : Buffer.from(JSON.stringify(payload));
	const input = `${b64url(Buffer.from(JSON.stringify(head)))}.${b64url(body)}`;
	return `${input}.${b64url(edSign(null, Buffer.from(input), TEST_KEY))}`;
}

export function keyDocument(keys: Map<string, string>): { keys: Record<string, string>[] } {
	return {
		keys: [...keys].map(([kid, x]) => ({ kid, kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x })),
	};
}

// A tools/call answer the way SealKeeper writes one.
export const toolResult = (data: Record<string, unknown>) => ({
	jsonrpc: '2.0',
	id: 1,
	result: {
		content: [
			{ type: 'text', text: 'answer' },
			{ type: 'text', text: JSON.stringify(data) },
		],
		structuredContent: data,
	},
});

// A get_trust answer. A shown one names the fixture agent by default.
export function trust(
	status: string,
	seal: string | null = null,
	agent?: Record<string, unknown> | null,
	extra: Record<string, unknown> = {},
): Record<string, unknown> {
	let named = agent;
	if (named === undefined && status === 'shown') {
		named = { id: FIXTURE_AGENT.id, handle: FIXTURE_AGENT.handle };
	}
	if (named === undefined && (status === 'checking' || status === 'delisted')) {
		named = {
			handle: FIXTURE_AGENT.handle,
			pageUrl: 'https://sealkeeper.run/agents/alice/fixture',
		};
	}
	return { skill: 'get-trust', status, agent: named ?? null, seal, ...extra };
}

export interface Reply {
	status: number;
	body: unknown;
	headers?: Record<string, string>;
}

export type Served = Reply | Error;

export const reply = (status = 200, body: unknown = null, headers = {}): Reply => ({
	status,
	body,
	headers,
});

export const answer = (data: Record<string, unknown>): Reply => reply(200, toolResult(data));

export function fromRecord(name: string): Reply {
	const record = recorded(name);
	return reply(record.status, record.body, record.headers);
}

const bytes = (body: unknown): Buffer =>
	body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(JSON.stringify(body));

// An error the way n8n's request helper throws one, with its code.
export function failure(name: string, code?: string): Error {
	const error = new Error(`${name} ${code ?? ''}`) as Error & { code?: string };
	error.name = name;
	if (code !== undefined) error.code = code;
	return error;
}

// A recorded SealKeeper behind n8n's request helper. Each URL answers its
// replies in order, the last one again once they run out, and every
// request is kept.
export class Server {
	readonly requests: IHttpRequestOptions[] = [];

	constructor(
		public mcp: Served[] = [],
		public keys: Served[] = [reply(200, FIXTURE_KEYS)],
	) {}

	readonly httpRequest = async (options: IHttpRequestOptions): Promise<unknown> => {
		this.requests.push(options);
		const queue = options.url === MCP_URL ? this.mcp : options.url === KEYS_URL ? this.keys : [];
		const item = queue.length > 1 ? queue.shift() : queue[0];
		if (item === undefined) throw new Error(`no reply for ${options.method} ${options.url}`);
		if (item instanceof Error) throw item;
		return {
			body: bytes(item.body),
			headers: { 'content-type': 'application/json', ...item.headers },
			statusCode: item.status,
			statusMessage: '',
		};
	};

	of(url: string): IHttpRequestOptions[] {
		return this.requests.filter((request) => request.url === url);
	}

	calls(): { params: { name: string; arguments: Record<string, unknown> } }[] {
		return this.of(MCP_URL).map((request) => JSON.parse(request.body as string));
	}
}

export class Clock {
	constructor(public now: number) {}
}

// The Io of a lookup over server, with waits recorded instead of waited.
export function ioOf(server: Server, clock: Clock, waits: number[] = []): Io {
	return {
		send: sendWith(server.httpRequest),
		sleep: async (milliseconds) => {
			waits.push(milliseconds);
		},
		now: () => clock.now,
		keys: new KeyCache(),
	};
}
