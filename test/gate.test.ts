// The gate, every rule of a pass and a block.

import { describe, expect, it } from 'vitest';

import { lookUp } from '../nodes/SealKeeper/client';
import { BLOCK_CODES, type Decision, PASS_CODES, blockOf, decide } from '../nodes/SealKeeper/gate';
import { SEAL_BROKEN_REASONS, type SubjectKind } from '../nodes/SealKeeper/seal';
import README from '../README.md?raw';
import {
	Clock,
	FIXTURE_AGENT,
	PINNED,
	PRODUCTION_KEYS,
	Server,
	TEST_AGENT_CLOCK,
	TEST_KEYS,
	answer,
	failure,
	fromRecord,
	ioOf,
	keyDocument,
	payloadOf,
	reply,
	sealFile,
	sign,
	trust,
} from './support';

const AGENT_SEAL = sealFile('v7-valid');
const SERVICE_SEAL = sealFile('v7-service-valid');
const LISTED_SEAL = sealFile('v7-listed-x402-valid');
const SERVICE_URL = 'https://pay.example.com/.well-known/x402';
const CARD_URL = 'https://agents.example.com/.well-known/agent-card.json';

// The gate's decision for target over server, as the node makes it.
async function check(
	server: Server,
	target = 'alice/fixture',
	kind: SubjectKind = 'agent',
	allowUnsealed = false,
	clock = new Clock(PINNED),
): Promise<Decision> {
	try {
		return decide(target, kind, await lookUp(ioOf(server, clock), target), allowUnsealed);
	} catch (error) {
		return blockOf(error);
	}
}

const decideOn = async (
	data: Record<string, unknown>,
	target = 'alice/fixture',
	kind: SubjectKind = 'agent',
	allowUnsealed = false,
) => await check(new Server([answer(data)]), target, kind, allowUnsealed);

const withheld = (value: unknown) => trust('shown', null, undefined, { withheld: value });

describe('a pass', () => {
	it('needs a current bronze SEAL of the kind', async () => {
		const decision = await decideOn(trust('shown', AGENT_SEAL));
		expect(decision.passed && [decision.code, decision.seal?.level]).toEqual(['sealed', 'bronze']);
	});

	it.each([['v4-valid'], ['v6-valid']])(
		'reads %s, from before subject, as an agent',
		async (name) => {
			expect((await decideOn(trust('shown', sealFile(name)))).code).toBe('sealed');
			expect(
				(await decideOn(trust('shown', sealFile(name)), 'alice/fixture', 'service')).code,
			).toBe('wrong_kind');
		},
	);

	it.each<[string, string, SubjectKind]>([
		[SERVICE_URL, SERVICE_SEAL, 'service'],
		['https://PAY.Example.COM/.well-known/x402', SERVICE_SEAL, 'service'],
		[CARD_URL, LISTED_SEAL, 'agent'],
	])('takes the URL %s when the SEAL names it', async (target, seal, kind) => {
		expect((await decideOn(trust('shown', seal), target, kind)).code).toBe('sealed');
	});

	it.each([['https://mcp.example.com'], ['https://MCP.example.com/']])(
		'reads the origin %s alone as its root',
		async (target) => {
			const service = {
				...payloadOf(SERVICE_SEAL),
				ver: 8,
				subject: { kind: 'service', interfaces: ['mcp'], paid: false },
				listing: {
					handle: 'example.com/mcp',
					domain_key: 'example.com',
					card_url: 'https://mcp.example.com/',
				},
			};
			const server = new Server(
				[answer(trust('shown', sign(service)))],
				[reply(200, keyDocument(TEST_KEYS))],
			);
			expect((await check(server, target, 'service')).code).toBe('sealed');
		},
	);

	it.each([
		['https://sealkeeper.run/agents/alice/fixture'],
		[`https://sealkeeper.run/agents/${FIXTURE_AGENT.id}`],
		[`https://api.sealkeeper.run/v1/agents/${FIXTURE_AGENT.id}/card`],
	])('needs no listing for the SealKeeper URL %s', async (target) => {
		expect((await decideOn(trust('shown', AGENT_SEAL), target)).code).toBe('sealed');
	});
});

describe('a block', () => {
	it('names the other kind as wrong_kind', async () => {
		const decision = await decideOn(trust('shown', SERVICE_SEAL));
		expect(decision).toEqual({
			passed: false,
			code: 'wrong_kind',
			reason: 'it holds a Service SEAL, not an Agent SEAL',
		});
		const other = await decideOn(trust('shown', AGENT_SEAL), 'alice/fixture', 'service');
		expect(other).toEqual({
			passed: false,
			code: 'wrong_kind',
			reason: 'it holds an Agent SEAL, not a Service SEAL',
		});
	});

	it('names level none as below_bronze', async () => {
		const server = new Server([fromRecord('get-trust-shown')], [reply(200, PRODUCTION_KEYS)]);
		const decision = await check(
			server,
			'sealkeeper/test-agent',
			'agent',
			false,
			new Clock(TEST_AGENT_CLOCK),
		);
		expect(decision).toEqual({
			passed: false,
			code: 'below_bronze',
			reason: 'its SEAL is below bronze',
		});
	});

	it.each([
		['https://pay.example.com/.well-known/X402', SERVICE_SEAL],
		['https://pay.example.com/.well-known/x402/', SERVICE_SEAL],
		['http://pay.example.com/.well-known/x402', SERVICE_SEAL],
		['https://other.example.com/.well-known/x402', SERVICE_SEAL],
		[SERVICE_URL, AGENT_SEAL],
	])('names the URL %s as wrong_url when the SEAL names another or none', async (target, seal) => {
		expect((await decideOn(trust('shown', seal), target, 'service')).code).toBe('wrong_url');
	});

	it('names a broken SEAL by its reason', async () => {
		const bad = await decideOn(trust('shown', sealFile('v1-bad-signature')));
		expect(bad).toEqual({
			passed: false,
			code: 'bad_signature',
			reason: 'broken SEAL: bad_signature',
		});
		expect((await decideOn(trust('shown', sealFile('v1-expired')))).code).toBe('expired');
	});
});

const UNSEALED: [string, Record<string, unknown>][] = [
	['not_found', trust('not_found', null, null)],
	['checking', trust('checking')],
	['checking', withheld({ code: 'checking' })],
	['no_seal', withheld({ code: 'no_seal', dormant_days: 93 })],
];
const ALWAYS_BLOCKED: [string, Record<string, unknown>][] = [
	['withheld', withheld({ code: 'withheld', reason: 'fraud' })],
	[
		'withheld',
		withheld({ code: 'withheld', reason: 'failed_checks', since: '2026-10-30T08:00:00.000Z' }),
	],
	['delisted', trust('delisted')],
	['unknown', trust('shown', null)],
	['unknown', withheld({ code: 'frozen' })],
	['unknown', { skill: 'get-trust', status: 'paused' }],
];

describe('no SEAL', () => {
	it.each([...UNSEALED, ...ALWAYS_BLOCKED])('blocks %s', async (code, data) => {
		const decision = await decideOn(data);
		expect([decision.passed, decision.code]).toEqual([false, code]);
	});

	it('says why each one blocks', async () => {
		const reasons = await Promise.all(
			[...UNSEALED, ...ALWAYS_BLOCKED].map(async ([, d]) => await decideOn(d)),
		);
		expect(reasons.map((d) => (d.passed ? null : d.reason))).toEqual([
			'SealKeeper knows no agent or service by that target',
			'SealKeeper is still checking it, so it holds no SEAL yet',
			'SealKeeper is still checking it, so it holds no SEAL yet',
			'it holds no SEAL, it has been dormant',
			'SealKeeper withholds its SEAL, reason fraud',
			'SealKeeper withholds its SEAL, reason failed_checks',
			'SealKeeper no longer lists it',
			'it holds no SEAL and SealKeeper says nothing more',
			'it holds no SEAL and SealKeeper says nothing more',
			'it holds no SEAL and SealKeeper says nothing more',
		]);
	});

	it('names a withheld SEAL with no reason', async () => {
		const decision = await decideOn(withheld({ code: 'withheld' }));
		expect(!decision.passed && decision.reason).toBe(
			'SealKeeper withholds its SEAL, reason no reason given',
		);
	});

	it.each(UNSEALED)('passes %s with allow unsealed', async (code, data) => {
		expect(await decideOn(data, 'alice/fixture', 'agent', true)).toEqual({
			passed: true,
			code,
			seal: null,
		});
	});

	it.each(ALWAYS_BLOCKED)('still blocks %s with allow unsealed', async (code, data) => {
		expect((await decideOn(data, 'alice/fixture', 'agent', true)).code).toBe(code);
	});

	it('still blocks a broken SEAL with allow unsealed', async () => {
		const data = trust('shown', sealFile('v1-unknown-kid'));
		expect((await decideOn(data, 'alice/fixture', 'agent', true)).code).toBe('unknown_kid');
	});
});

describe('a failure', () => {
	it.each<[string, () => Server, string]>([
		['a 503', () => new Server([reply(503, Buffer.alloc(0))]), 'unavailable'],
		[
			'a refused connection',
			() => new Server([failure('AxiosError', 'ECONNREFUSED')]),
			'unavailable',
		],
		[
			'keys that cannot be had',
			() =>
				new Server([answer(trust('shown', AGENT_SEAL))], [failure('AxiosError', 'ECONNREFUSED')]),
			'unavailable',
		],
		['a tool error', () => new Server([fromRecord('get-trust-is-error')]), 'bad_target'],
		['a JSON-RPC error', () => new Server([fromRecord('unknown-tool')]), 'error'],
	] as [string, () => Server, string][])('blocks %s and never throws', async (_, server, code) => {
		expect((await check(server())).code).toBe(code);
	});

	it('blocks as unavailable even with allow unsealed', async () => {
		const decision = await check(
			new Server([reply(503, Buffer.alloc(0))]),
			'alice/fixture',
			'agent',
			true,
		);
		expect(decision.code).toBe('unavailable');
	});

	it('blocks a bad target with the server line', async () => {
		expect((await check(new Server([fromRecord('get-trust-is-error')]), ' ')).code).toBe(
			'bad_target',
		);
		const decision = await check(new Server([fromRecord('get-trust-is-error')]), 'x');
		expect(!decision.passed && decision.reason).toMatch(/^agent: Too small/);
	});

	it('blocks anything else that throws as an error', () => {
		expect(blockOf(new RangeError('boom'))).toEqual({
			passed: false,
			code: 'error',
			reason: 'unexpected RangeError',
		});
	});
});

describe('the codes', () => {
	it('end with the broken SEAL reasons and never repeat', () => {
		expect(BLOCK_CODES.slice(-SEAL_BROKEN_REASONS.length)).toEqual([...SEAL_BROKEN_REASONS]);
		expect(new Set(BLOCK_CODES).size).toBe(BLOCK_CODES.length);
		expect(PASS_CODES).toEqual(['sealed', 'not_found', 'checking', 'no_seal']);
	});

	it('reads an answer that is no tool result as error', async () => {
		expect((await check(new Server([reply(200, Buffer.from('[]'))]))).code).toBe('error');
	});

	it('names every block and pass code in the README', () => {
		for (const code of [...BLOCK_CODES, ...PASS_CODES]) expect(README).toContain(`\`${code}\``);
	});
});
