// Every SEAL case of the reader fixtures, at the pinned clock and from the
// day after.

import { describe, expect, it } from 'vitest';

import { readKeys, verifyWithKeys } from '../nodes/SealKeeper/seal';
import { FIXTURE_AGENT, FIXTURE_KEYS, INDEX, NOW_FROM, PINNED, sealFile } from './support';

const KEYS = readKeys(FIXTURE_KEYS) ?? new Map<string, string>();
const SEAL_CASES = INDEX.cases.filter((c) => c.kind === 'seal');
// The fixtures also hold handshakes and SEAL route answers, which this node
// does not read.
const OTHER_KINDS = new Set(['handshake', 'read']);

interface Expected {
	valid: boolean;
	reason?: string;
	payload?: Record<string, unknown> & {
		sub: string;
		level: string;
		iat: number;
		exp: number;
		trust?: number;
		subject?: { kind: string };
	};
}

function check(name: string, expected: Expected, now: number) {
	const got = verifyWithKeys(sealFile(name), KEYS, now, FIXTURE_AGENT.id);
	if (!expected.valid) {
		expect(got).toEqual({ broken: expected.reason });
		return;
	}
	if (!('seal' in got)) throw new Error(`${name} is broken, ${got.broken}`);
	const { seal } = got;
	const payload = expected.payload;
	if (payload === undefined) throw new Error(`${name} names no payload`);
	expect(seal.payload).toEqual(payload);
	expect(seal.agentId).toBe(payload.sub);
	expect(seal.level).toBe(payload.level);
	expect(seal.trust).toBe(payload.trust ?? null);
	expect(seal.kind).toBe(payload.subject?.kind ?? 'agent');
	expect([seal.issuedAt, seal.expiresAt]).toEqual([payload.iat, payload.exp]);
}

describe('the reader fixtures', () => {
	it('holds only SEAL cases and kinds this node does not read', () => {
		const kinds = new Set(INDEX.cases.map((c) => c.kind));
		expect(kinds.has('seal')).toBe(true);
		for (const kind of kinds) expect(kind === 'seal' || OTHER_KINDS.has(kind)).toBe(true);
	});

	it.each(SEAL_CASES.map((c) => [c.name, c] as const))(
		'%s answers as the index says at the pinned clock',
		(name, c) => {
			check(name, c.expected.pinned as Expected, PINNED);
		},
	);

	it.each(SEAL_CASES.map((c) => [c.name, c] as const))(
		'%s answers as the index says from the day after',
		(name, c) => {
			check(name, c.expected.now as Expected, NOW_FROM);
		},
	);
});
