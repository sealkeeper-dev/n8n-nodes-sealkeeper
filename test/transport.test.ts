// The requests the node sends through n8n's request helper and how it reads
// every kind of answer.

import { describe, expect, it } from 'vitest';

import { lookUp } from '../nodes/SealKeeper/client';
import { BadTargetError, SealKeeperError, UnavailableError } from '../nodes/SealKeeper/protocol';
import { VERSION } from '../nodes/SealKeeper/version';
import pkg from '../package.json';
import {
	Clock,
	FIXTURE_AGENT,
	MCP_URL,
	type Served,
	Server,
	answer,
	failure,
	fromRecord,
	ioOf,
	reply,
	trust,
} from './support';

const CLOCK = new Clock(1_790_856_000);
const NOT_FOUND = trust('not_found', null, null);

async function run(server: Server, target: unknown = 'alice/helper', waits: number[] = []) {
	return await lookUp(ioOf(server, CLOCK, waits), target as string);
}

async function refusal(served: Served[], target: unknown = 'alice/helper'): Promise<unknown> {
	return await run(new Server(served), target).then(
		() => null,
		(error: unknown) => error,
	);
}

describe('the request', () => {
	it('is one stateless tools/call with the headers, a timeout and no redirect', async () => {
		const server = new Server([answer(NOT_FOUND)]);
		expect((await run(server)).code).toBe('not_found');
		expect(server.requests).toHaveLength(1);
		const [request] = server.requests;
		expect(request.method).toBe('POST');
		expect(request.url).toBe(MCP_URL);
		expect(request.qs).toBeUndefined();
		expect(request.headers).toEqual({
			'content-type': 'application/json',
			accept: 'application/json, text/event-stream',
			'mcp-protocol-version': '2025-11-25',
			'user-agent': `n8n-nodes-sealkeeper/${VERSION}`,
		});
		expect(request).toMatchObject({
			timeout: 5000,
			disableFollowRedirect: true,
			ignoreHttpStatusErrors: true,
			returnFullResponse: true,
			encoding: 'arraybuffer',
			json: false,
			maxResponseBodyBytes: 65536,
		});
		expect(request.abortSignal).toBeInstanceOf(AbortSignal);
		expect(JSON.parse(request.body as string)).toEqual({
			jsonrpc: '2.0',
			id: 1,
			method: 'tools/call',
			params: { name: 'get_trust', arguments: { agent: 'alice/helper' } },
		});
	});

	it('names the package version of package.json', () => {
		expect(VERSION).toBe(pkg.version);
	});

	it.each([
		['alice/helper'],
		['https://sealkeeper.run/agents/alice/helper'],
		['https://agents.example.com/.well-known/agent-card.json'],
		['https://mcp.example.com/mcp'],
		['https://[not-a-host/x'],
	])('sends %s as given', async (target) => {
		const server = new Server([answer(NOT_FOUND)]);
		await run(server, target);
		expect(server.calls()[0].params.arguments).toEqual({ agent: target });
	});

	it.each([[FIXTURE_AGENT.id], [FIXTURE_AGENT.did]])(
		'sends the agent id or did:key %s as its page URL',
		async (target) => {
			const server = new Server([answer(NOT_FOUND)]);
			await run(server, target);
			expect(server.calls()[0].params.arguments).toEqual({
				agent: `https://sealkeeper.run/agents/${FIXTURE_AGENT.id}`,
			});
		},
	);

	it.each([[''], ['   '], ['did:key:z6MkNotAKey'], [null], [7]])(
		'refuses the target %j without a request',
		async (target) => {
			const server = new Server([answer(NOT_FOUND)]);
			await expect(run(server, target)).rejects.toBeInstanceOf(BadTargetError);
			expect(server.requests).toEqual([]);
		},
	);
});

describe('the answer', () => {
	it('reads a tool error as a bad target with the server line', async () => {
		const error = await refusal([fromRecord('get-trust-is-error')]);
		expect(error).toBeInstanceOf(BadTargetError);
		expect((error as Error).message).toMatch(/^agent: Too small/);
	});

	it.each([
		['unknown-tool', 'SealKeeper answered an error: Unknown tool'],
		['query-400', 'SealKeeper refused the request, HTTP 400: Invalid query'],
	])('reads the recorded %s as an error', async (record, message) => {
		const error = await refusal([fromRecord(record)]);
		expect((error as Error).constructor).toBe(SealKeeperError);
		expect((error as Error).message).toBe(message);
	});

	it('reads a 413 as an error', async () => {
		const tooLarge = {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32600, message: 'The request is larger than 17408 bytes' },
		};
		const error = await refusal([reply(413, tooLarge)]);
		expect((error as Error).constructor).toBe(SealKeeperError);
		expect((error as Error).message).toMatch(/HTTP 413/);
	});

	it.each([
		[Buffer.from('not json')],
		[Buffer.from('[]')],
		[Buffer.from('{"jsonrpc":"2.0","id":1}')],
		[Buffer.from('{"jsonrpc":"2.0","id":1,"result":{"content":[]}}')],
		[Buffer.from([0xff, 0xfe])],
	])('reads %s, which is no tool result, as an error', async (body) => {
		const error = await refusal([reply(200, body)]);
		expect((error as Error).constructor).toBe(SealKeeperError);
	});

	it('does not follow a redirect', async () => {
		const server = new Server([
			reply(302, Buffer.alloc(0), { location: 'https://elsewhere.example/' }),
		]);
		await expect(run(server)).rejects.toThrow('HTTP 302');
		expect(server.requests).toHaveLength(1);
	});

	it.each([[500], [502], [503]])('reads a %i as unavailable', async (status) => {
		expect(await refusal([reply(status, Buffer.alloc(0))])).toBeInstanceOf(UnavailableError);
	});

	it.each([
		[failure('AxiosError', 'ECONNABORTED'), 'did not answer within 5 seconds'],
		[failure('AxiosError', 'ETIMEDOUT'), 'did not answer within 5 seconds'],
		[failure('CanceledError', 'ERR_CANCELED'), 'did not answer within 5 seconds'],
		[failure('TimeoutError'), 'did not answer within 5 seconds'],
		[failure('AxiosError', 'ECONNREFUSED'), 'could not reach SealKeeper, AxiosError'],
		[failure('SsrfBlockedIpError'), 'could not reach SealKeeper, SsrfBlockedIpError'],
	])('reads a thrown %s as unavailable', async (thrown, message) => {
		const error = await refusal([thrown]);
		expect(error).toBeInstanceOf(UnavailableError);
		expect((error as Error).message).toContain(message);
	});

	it('refuses an answer past 64 KB, capped by n8n or read whole', async () => {
		const capped = await refusal([failure('HttpResponseSizeLimitError', 'ERR_RESPONSE_TOO_LARGE')]);
		const whole = await refusal([reply(200, Buffer.alloc(64 * 1024 + 1, 0x20))]);
		for (const error of [capped, whole]) {
			expect((error as Error).constructor).toBe(SealKeeperError);
			expect((error as Error).message).toBe("SealKeeper's answer is larger than 65536 bytes");
		}
	});

	it('waits for Retry-After on a 429 and tries once more', async () => {
		const waits: number[] = [];
		const limited = reply(429, { error: { code: 'rate_limited' } }, { 'retry-after': '2' });
		const server = new Server([limited, answer(NOT_FOUND)]);
		expect((await run(server, 'alice/helper', waits)).code).toBe('not_found');
		expect(waits).toEqual([2000]);
		expect(server.requests).toHaveLength(2);
	});

	it('reads a second 429 as unavailable', async () => {
		const waits: number[] = [];
		const limited = reply(429, { error: { code: 'rate_limited' } }, { 'retry-after': '1' });
		const server = new Server([limited, limited, answer(NOT_FOUND)]);
		await expect(run(server, 'alice/helper', waits)).rejects.toBeInstanceOf(UnavailableError);
		expect(waits).toEqual([1000]);
		expect(server.requests).toHaveLength(2);
	});

	it.each([
		[{}],
		[{ 'retry-after': '60' }],
		[{ 'retry-after': 'soon' }],
		[{ 'retry-after': '-1' }],
	])('reads a 429 with %j as unavailable at once', async (headers) => {
		const waits: number[] = [];
		const server = new Server([
			reply(429, { error: { code: 'rate_limited' } }, headers),
			answer(NOT_FOUND),
		]);
		await expect(run(server, 'alice/helper', waits)).rejects.toBeInstanceOf(UnavailableError);
		expect(waits).toEqual([]);
		expect(server.requests).toHaveLength(1);
	});
});
