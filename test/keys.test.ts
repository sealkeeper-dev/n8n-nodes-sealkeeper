// The key copy behind verify. Kept five minutes, fetched again for an
// unknown kid, and never used past its age when a fetch fails.

import { describe, expect, it } from 'vitest';

import { type Io, verify } from '../nodes/SealKeeper/client';
import { UnavailableError } from '../nodes/SealKeeper/protocol';
import { VERSION } from '../nodes/SealKeeper/version';
import {
	Clock,
	FIXTURE_AGENT,
	FIXTURE_KEYS,
	KEYS_URL,
	PINNED,
	type Served,
	Server,
	TEST_KEYS,
	failure,
	ioOf,
	keyDocument,
	payloadOf,
	reply,
	sealFile,
	sign,
} from './support';

const AGENT = FIXTURE_AGENT.id;
const ROTATED = { keys: [keyDocument(TEST_KEYS).keys[0], ...FIXTURE_KEYS.keys] };

async function reason(io: Io, seal: string): Promise<string | null> {
	const got = await verify(io, seal, AGENT);
	return 'broken' in got ? got.broken : null;
}

describe('the key copy', () => {
	it('is fetched from sealkeeper.run once for five minutes', async () => {
		const server = new Server();
		const clock = new Clock(PINNED);
		const io = ioOf(server, clock);
		expect(await reason(io, sealFile('v1-valid'))).toBeNull();
		clock.now = PINNED + 299;
		expect(await reason(io, sealFile('v4-valid'))).toBeNull();
		expect(server.of(KEYS_URL)).toHaveLength(1);
		const [request] = server.of(KEYS_URL);
		expect(request.method).toBe('GET');
		expect(request.body).toBeUndefined();
		expect(request.headers).toEqual({
			accept: 'application/json',
			'user-agent': `n8n-nodes-sealkeeper/${VERSION}`,
		});
		expect(request).toMatchObject({ timeout: 5000, disableFollowRedirect: true });
		clock.now = PINNED + 300;
		await reason(io, sealFile('v1-valid'));
		expect(server.of(KEYS_URL)).toHaveLength(2);
	});

	it('is fetched again when dated after now', async () => {
		const server = new Server();
		const clock = new Clock(PINNED);
		const io = ioOf(server, clock);
		await reason(io, sealFile('v1-valid'));
		clock.now = PINNED - 1;
		await reason(io, sealFile('v1-valid'));
		expect(server.of(KEYS_URL)).toHaveLength(2);
	});

	it('is fetched again once for an unknown kid, which stays unknown_kid', async () => {
		const server = new Server();
		const io = ioOf(server, new Clock(PINNED));
		await reason(io, sealFile('v1-valid'));
		expect(await reason(io, sealFile('v1-unknown-kid'))).toBe('unknown_kid');
		expect(server.of(KEYS_URL)).toHaveLength(2);
	});

	it('finds a kid added since the last copy by fetching again', async () => {
		const server = new Server([], [reply(200, FIXTURE_KEYS), reply(200, ROTATED)]);
		const io = ioOf(server, new Clock(PINNED));
		await reason(io, sealFile('v1-valid'));
		const fresh = sign(payloadOf(sealFile('v4-valid')));
		const got = await verify(io, fresh, AGENT);
		expect('seal' in got && got.seal.trust).toBe(412);
		expect(server.of(KEYS_URL)).toHaveLength(2);
	});

	it('is not fetched for a malformed header', async () => {
		const server = new Server();
		expect(await reason(ioOf(server, new Clock(PINNED)), 'not a seal')).toBe('malformed');
		expect(server.requests).toEqual([]);
	});

	it.each<[string, Served]>([
		['refused', failure('AxiosError', 'ECONNREFUSED')],
		['timed out', failure('AxiosError', 'ECONNABORTED')],
		['503', reply(503, Buffer.alloc(0))],
		['404', reply(404, Buffer.alloc(0))],
		['not json', reply(200, Buffer.from('not json'))],
		['no keys', reply(200, { keys: [] })],
	])('with no copy, a fetch that is %s is unavailable', async (_, served) => {
		const io = ioOf(new Server([], [served]), new Clock(PINNED));
		await expect(verify(io, sealFile('v1-valid'), AGENT)).rejects.toBeInstanceOf(UnavailableError);
	});

	it('is never used past its age when the fetch fails', async () => {
		const server = new Server(
			[],
			[reply(200, FIXTURE_KEYS), failure('AxiosError', 'ECONNREFUSED')],
		);
		const clock = new Clock(PINNED);
		const io = ioOf(server, clock);
		await reason(io, sealFile('v1-valid'));
		clock.now = PINNED + 300;
		await expect(verify(io, sealFile('v1-valid'), AGENT)).rejects.toBeInstanceOf(UnavailableError);
	});

	it('answers unavailable for an unknown kid when the fetch fails', async () => {
		const server = new Server(
			[],
			[reply(200, FIXTURE_KEYS), failure('AxiosError', 'ECONNREFUSED')],
		);
		const io = ioOf(server, new Clock(PINNED));
		await reason(io, sealFile('v1-valid'));
		await expect(verify(io, sealFile('v1-unknown-kid'), AGENT)).rejects.toBeInstanceOf(
			UnavailableError,
		);
	});
});
