// lookUp, every get_trust status and every reason a SEAL is missing.

import { describe, expect, it } from 'vitest';

import { type Lookup, lookUp } from '../nodes/SealKeeper/client';
import { SealKeeperError } from '../nodes/SealKeeper/protocol';
import {
	Clock,
	FIXTURE_AGENT,
	PINNED,
	PRODUCTION_KEYS,
	Server,
	TEST_AGENT_CLOCK,
	TEST_AGENT_ID,
	answer,
	fromRecord,
	ioOf,
	reply,
	sealFile,
	trust,
} from './support';

const OTHER = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const HOLD_REASONS = [
	'fraud',
	'collusion',
	'safety',
	'operator_ban',
	'key_compromise',
	'failed_checks',
	'no_recent_check',
	'wallet_unproven_change',
	'price_above_declared',
	'mcp_hidden_text',
	'mcp_change_unresolved',
];
const SINCE = '2026-10-30T08:00:00.000Z';

async function lookup(data: Record<string, unknown>, target = 'alice/fixture'): Promise<Lookup> {
	return await lookUp(ioOf(new Server([answer(data)]), new Clock(PINNED)), target);
}

const withheld = (value: unknown) => trust('shown', null, undefined, { withheld: value });

describe('lookUp', () => {
	it('verifies the recorded test agent SEAL with the production keys', async () => {
		const server = new Server([fromRecord('get-trust-shown')], [reply(200, PRODUCTION_KEYS)]);
		const found = await lookUp(ioOf(server, new Clock(TEST_AGENT_CLOCK)), 'sealkeeper/test-agent');
		expect(found.seal).not.toBeNull();
		expect([found.status, found.seal?.kind, found.seal?.level, found.seal?.trust]).toEqual([
			'shown',
			'agent',
			'none',
			0,
		]);
		expect(found.seal?.agentId).toBe(TEST_AGENT_ID);
		expect(found.seal?.payload.ver).toBe(9);
		expect(found.handle).toBe('sealkeeper/test-agent');
		expect(found.code).toBeNull();
	});

	it.each([
		['v7-valid', 'agent', 412],
		['v7-service-valid', 'service', 412],
		['v6-valid', 'agent', 412],
	])('reads kind, level and trust of %s from the verified SEAL only', async (name, kind, score) => {
		const unsigned = {
			id: FIXTURE_AGENT.id,
			handle: 'alice/fixture',
			level: 'gold',
			trust: 9999,
			subjectKind: 'robot',
		};
		const found = await lookup(trust('shown', sealFile(name), unsigned));
		expect([found.seal?.kind, found.seal?.level]).toEqual([kind, 'bronze']);
		expect([score, 0]).toContain(found.seal?.trust);
		expect(found.code).toBeNull();
	});

	it('reads a broken SEAL as no SEAL with its reason', async () => {
		const found = await lookup(trust('shown', sealFile('v1-bad-signature')));
		expect([found.seal, found.code, found.broken]).toEqual([null, 'broken', 'bad_signature']);
	});

	it('reads a SEAL for another agent than the answer names as wrong_agent', async () => {
		const found = await lookup(trust('shown', sealFile('v7-valid'), { id: OTHER }));
		expect(found.broken).toBe('wrong_agent');
	});

	it('checks the SEAL against the id the target names', async () => {
		const answered = trust('shown', sealFile('v7-valid'));
		expect((await lookup(answered, FIXTURE_AGENT.did)).seal).not.toBeNull();
		expect(
			(await lookup(answered, `https://sealkeeper.run/agents/${FIXTURE_AGENT.id}`)).seal,
		).not.toBeNull();
		expect((await lookup(answered, OTHER)).broken).toBe('wrong_agent');
		const card = `https://api.sealkeeper.run/v1/agents/${OTHER}/card`;
		expect((await lookup(answered, card)).broken).toBe('wrong_agent');
	});

	it.each([['checking'], ['delisted']])('reads a listed agent that is %s', async (status) => {
		const found = await lookup(trust(status));
		expect([found.status, found.code, found.seal]).toEqual([status, status, null]);
		expect(found.handle).toBe('alice/fixture');
	});

	it('reads the recorded not_found answer as not_found', async () => {
		const server = new Server([fromRecord('get-trust-not-found')]);
		const found = await lookUp(ioOf(server, new Clock(PINNED)), 'alice/no-such-agent');
		expect([found.status, found.code, found.handle]).toEqual(['not_found', 'not_found', null]);
	});

	it('reads a shown answer with no SEAL and nothing more as unknown', async () => {
		const data = trust('shown', null);
		const found = await lookup(data);
		expect([found.code, found.raw]).toEqual(['unknown', data]);
	});

	it.each(HOLD_REASONS.map((r) => [r]))(
		'reads a SEAL withheld for %s with its since',
		async (why) => {
			const found = await lookup(withheld({ code: 'withheld', reason: why, since: SINCE }));
			expect([found.code, found.reason, found.since, found.raw]).toEqual([
				'withheld',
				why,
				SINCE,
				null,
			]);
		},
	);

	it('reads a withheld SEAL with no since or a new reason as sent', async () => {
		const found = await lookup(withheld({ code: 'withheld', reason: 'a_new_reason' }));
		expect([found.code, found.reason, found.since]).toEqual(['withheld', 'a_new_reason', null]);
	});

	it.each([[93], [null], [-1], ['93'], [1.5]])(
		'reads no_seal with dormant days %j',
		async (days) => {
			const found = await lookup(withheld({ code: 'no_seal', dormant_days: days }));
			expect(found.code).toBe('no_seal');
			expect(found.dormantDays).toBe(days === 93 ? 93 : null);
		},
	);

	it('reads a withheld checking code as checking', async () => {
		const found = await lookup(withheld({ code: 'checking' }));
		expect([found.status, found.code]).toEqual(['shown', 'checking']);
	});

	it.each([
		[{ code: 'frozen', until: 1 }, 'frozen'],
		[{ code: 7 }, 'unknown'],
		['withheld', 'unknown'],
	])('passes the withheld %j it does not know through with the answer', async (value, code) => {
		const data = withheld(value);
		const found = await lookup(data);
		expect([found.code, found.raw]).toEqual([code, data]);
	});

	it('reads a status it does not know as unknown with the answer', async () => {
		const data = { skill: 'get-trust', status: 'paused', agent: null, seal: null };
		const found = await lookup(data);
		expect([found.status, found.code, found.raw]).toEqual(['paused', 'unknown', data]);
	});

	it.each([
		[trust('shown', sealFile('v7-valid'), { handle: 'alice/fixture' })],
		[trust('shown', 12 as unknown as string)],
	])('throws for a shown SEAL with no agent id or no string', async (data) => {
		await expect(lookup(data)).rejects.toBeInstanceOf(SealKeeperError);
	});
});
