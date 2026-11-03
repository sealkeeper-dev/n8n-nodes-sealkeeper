// verifyWithKeys, each step of verification and the shape it reads, and
// agentIdFromDidKey against an independent encoder.

import { describe, expect, it } from 'vitest';

import {
	SEAL_VERSIONS,
	agentIdFromDidKey,
	isCurrent,
	readKeys,
	verifyWithKeys,
} from '../nodes/SealKeeper/seal';
import { FIXTURE_AGENT, TEST_KEYS, b64url, sealFile, sign } from './support';

const AGENT = FIXTURE_AGENT.id;
const OTHER = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';
const NOW = 1_790_856_000;
const DROP = Symbol('drop');

type Fields = Record<string, unknown>;

// The fields this node reads at version, valid at NOW, with fields over
// them. DROP leaves a field out.
function payload(version: unknown = 9, fields: Fields = {}): Fields {
	const p: Fields = {
		iss: 'sealkeeper.run',
		sub: AGENT,
		ver: version,
		iat: NOW - 60,
		exp: NOW - 60 + 86400,
		level: 'bronze',
	};
	if (typeof version === 'number' && version >= 4) p.trust = 7;
	if (typeof version === 'number' && version >= 7) p.subject = { kind: 'agent' };
	Object.assign(p, fields);
	return Object.fromEntries(Object.entries(p).filter(([, v]) => v !== DROP));
}

function reason(seal: unknown, now = NOW, agent = AGENT, keys = TEST_KEYS): string | null {
	const got = verifyWithKeys(seal, keys, now, agent);
	return 'broken' in got ? got.broken : null;
}

function verified(seal: string, now = NOW) {
	const got = verifyWithKeys(seal, TEST_KEYS, now, AGENT);
	if (!('seal' in got)) throw new Error(`broken, ${got.broken}`);
	return got.seal;
}

function flipSignature(seal: string): string {
	const [head, body, sig] = seal.split('.');
	const raw = Buffer.from(sig, 'base64url');
	raw[0] ^= 1;
	return `${head}.${body}.${b64url(raw)}`;
}

describe('verifyWithKeys', () => {
	it.each(SEAL_VERSIONS.map((ver) => [ver]))('reads version %i', (ver) => {
		const seal = verified(sign(payload(ver)));
		expect([seal.level, seal.kind, seal.trust]).toEqual(['bronze', 'agent', ver >= 4 ? 7 : null]);
	});

	it.each([[0], [10], ['9'], [true], [null], [9.5], [DROP]])(
		'refuses version %s as unsupported_version',
		(ver) => {
			expect(reason(sign(payload(9, { ver })))).toBe('unsupported_version');
		},
	);

	it('reads a whole number written with a point', () => {
		const text = JSON.stringify(payload(9)).replace('"ver":9', '"ver":9.0');
		expect(verified(sign(Buffer.from(text))).payload.ver).toBe(9);
	});

	it.each([
		[{ alg: 'none', kid: 'test-1' }],
		[{ alg: 'EdDSA' }],
		[{ alg: 'EdDSA', kid: '' }],
		[{ alg: 'EdDSA', kid: 'k'.repeat(129) }],
		[{ alg: 'EdDSA', kid: 'test-1', typ: 'JWT' }],
		[{ alg: 'EdDSA', kid: 1 }],
		[['EdDSA', 'test-1']],
	])('reads header %j as malformed', (header) => {
		expect(reason(sign(payload(), 'test-1', header))).toBe('malformed');
	});

	it.each([
		[''],
		['a.b'],
		['a.b.c.d'],
		['a..c'],
		['a.b.c='],
		['a b.c.d'],
		[null],
		[12],
		['x'.repeat(262145)],
	])('reads %j as malformed', (seal) => {
		expect(reason(seal)).toBe('malformed');
	});

	it('drops surrounding whitespace', () => {
		expect(reason(`  ${sign(payload())}\n`)).toBeNull();
	});

	it('answers a kid not among the keys as unknown_kid', () => {
		expect(reason(sign(payload(), 'test-9'))).toBe('unknown_kid');
	});

	it('finds the key by kid, not by position', () => {
		const keys = new Map([
			['a', OTHER],
			['test-1', TEST_KEYS.get('test-1') as string],
		]);
		expect(reason(sign(payload()), NOW, AGENT, keys)).toBeNull();
	});

	it('answers one changed byte of the signature as bad_signature', () => {
		expect(reason(flipSignature(sign(payload())))).toBe('bad_signature');
	});

	it('answers a changed payload as bad_signature before any time check', () => {
		const [head, , sig] = sign(payload()).split('.');
		const other = b64url(Buffer.from(JSON.stringify(payload(9, { level: 'gold' }))));
		expect(reason(`${head}.${other}.${sig}`, 0)).toBe('bad_signature');
	});

	it('answers a signature of the wrong length as bad_signature', () => {
		const [head, body] = sign(payload()).split('.');
		expect(reason(`${head}.${body}.${b64url(Buffer.alloc(63))}`)).toBe('bad_signature');
	});

	it('reads a signed payload that is not JSON as malformed', () => {
		expect(reason(sign(Buffer.from('not json')))).toBe('malformed');
		expect(reason(sign(Buffer.from('{"ver": NaN}')))).toBe('malformed');
	});

	it('reads past a byte order mark before the payload', () => {
		const text = Buffer.concat([
			Buffer.from([0xef, 0xbb, 0xbf]),
			Buffer.from(JSON.stringify(payload())),
		]);
		expect(reason(sign(text))).toBeNull();
	});

	it.each([['sealkeeper.dev'], [null], [1], [DROP]])('answers issuer %s as wrong_issuer', (iss) => {
		expect(reason(sign(payload(9, { iss })))).toBe('wrong_issuer');
	});

	it('answers a payload that is not an object as wrong_issuer', () => {
		expect(reason(sign([1, 2]))).toBe('wrong_issuer');
	});

	it('checks the issuer before the version and the shape', () => {
		expect(reason(sign(payload(9, { iss: 'x', ver: 99, level: 'platinum' })))).toBe('wrong_issuer');
	});

	it.each([
		[{ sub: 'not-an-id' }],
		[{ sub: DROP }],
		[{ level: 'platinum' }],
		[{ level: DROP }],
		[{ iat: -1 }],
		[{ iat: 'now' }],
		[{ exp: NOW - 60 }],
		[{ exp: NOW - 60 + 86401 }],
		[{ exp: 2 ** 53 }],
		[{ trust: -1 }],
		[{ trust: DROP }],
		[{ trust: 1.5 }],
		[{ subject: DROP }],
		[{ subject: { kind: 'robot' } }],
		[{ subject: 'agent' }],
		[{ listing: { handle: 'a/b' } }],
		[{ listing: { card_url: 'ftp://example.com/card' } }],
		[{ listing: null }],
	])('reads %j as malformed', (fields) => {
		expect(reason(sign(payload(9, fields)))).toBe('malformed');
	});

	it.each([
		[3, 'trust', 1],
		[6, 'subject', { kind: 'agent' }],
		[4, 'listing', { card_url: 'https://x.example/' }],
	])('reads version %i with %s as malformed', (ver, field, value) => {
		expect(reason(sign(payload(ver, { [field]: value })))).toBe('malformed');
	});

	it('reads a SEAL before version 7 as an agent', () => {
		expect(verified(sign(payload(6))).kind).toBe('agent');
	});

	it('reads the kind of a Service SEAL', () => {
		const seal = sign(
			payload(9, { subject: { kind: 'service', interfaces: ['mcp'], paid: false } }),
		);
		expect(verified(seal).kind).toBe('service');
	});

	it('does not check a field it does not read', () => {
		expect(reason(sign(payload(9, { counts: 'anything' })))).toBeNull();
	});

	it('needs exp a whole second ahead', () => {
		const seal = sign(payload(9, { iat: NOW - 100, exp: NOW + 1 }));
		expect(reason(seal, NOW)).toBeNull();
		expect(reason(seal, NOW + 0.5)).toBe('expired');
		expect(reason(seal, NOW + 1)).toBe('expired');
	});

	it('takes iat at most 300 seconds ahead', () => {
		expect(reason(sign(payload(9, { iat: NOW + 300, exp: NOW + 1000 })))).toBeNull();
		expect(reason(sign(payload(9, { iat: NOW + 301, exp: NOW + 1000 })))).toBe('not_yet_valid');
	});

	it('checks expiry before iat and sub', () => {
		expect(reason(sign(payload(9, { iat: NOW - 1000, exp: NOW - 10 })), NOW, OTHER)).toBe(
			'expired',
		);
	});

	it('answers a valid SEAL for another agent as wrong_agent', () => {
		expect(reason(sign(payload()), NOW, OTHER)).toBe('wrong_agent');
	});

	it('reads exp against the clock for isCurrent', () => {
		const seal = verified(sign(payload(9, { exp: NOW + 10 })));
		expect(isCurrent(seal, NOW + 9)).toBe(true);
		expect(isCurrent(seal, NOW + 9.5)).toBe(false);
	});

	it('answers the fixture SEAL as unknown_kid with the test keys', () => {
		expect(reason(sealFile('v1-valid'), 1790856000)).toBe('unknown_kid');
	});
});

describe('readKeys', () => {
	it('keeps only Ed25519 keys and the first of a kid', () => {
		const good = { kid: 'k1', kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', x: AGENT };
		const keys = readKeys({
			keys: [
				good,
				{ ...good, x: OTHER },
				{ ...good, kid: 'k2', crv: 'X25519' },
				{ ...good, kid: 'k3', x: 'short' },
				'not a key',
			],
		});
		expect(keys).toEqual(new Map([['k1', AGENT]]));
	});

	it.each([[null], [[]], [{ keys: [] }], [{ keys: 'k1' }], [{ keys: [{ kid: 'k1' }] }]])(
		'reads %j as no keys',
		(doc) => {
			expect(readKeys(doc)).toBeNull();
		},
	);
});

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
// The agent ids of the two Ed25519 test vectors of RFC 8032.
const VECTOR_IDS = [
	'11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
	'PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw',
];

function base58(raw: Buffer): string {
	let zeros = 0;
	while (zeros < raw.length && raw[zeros] === 0) zeros++;
	let n = BigInt(`0x${raw.toString('hex') || '0'}`);
	let out = '';
	while (n > BigInt(0)) {
		out = ALPHABET[Number(n % BigInt(58))] + out;
		n /= BigInt(58);
	}
	return '1'.repeat(zeros) + out;
}

const keyBytes = (agentId: string) => Buffer.from(agentId, 'base64url');
const MULTICODEC = Buffer.from([0xed, 0x01]);
const didOf = (agentId: string) =>
	`did:key:z${base58(Buffer.concat([MULTICODEC, keyBytes(agentId)]))}`;

describe('agentIdFromDidKey', () => {
	it('reads the fixture agent did', () => {
		expect(agentIdFromDidKey(FIXTURE_AGENT.did)).toBe(FIXTURE_AGENT.id);
		expect(didOf(FIXTURE_AGENT.id)).toBe(FIXTURE_AGENT.did);
	});

	it('reads the example of the SEAL format', () => {
		const did = 'did:key:z6Mkr73sdsBsqzmSrDUQPFHQAu5BewVajoLHyoG92ktE1xyf';
		expect(agentIdFromDidKey(did)).toBe('rR7dStS9oIU4l8V4C1OJdW2VzcjgTS3m2qjLLwm2NYI');
	});

	it.each(VECTOR_IDS.map((id) => [id]))('round trips the test vector %s', (agentId) => {
		const did = didOf(agentId);
		expect(did.startsWith('did:key:z6Mk')).toBe(true);
		expect(did.length).toBe('did:key:z6Mk'.length + 44);
		expect(agentIdFromDidKey(did)).toBe(agentId);
	});

	it.each([[0x00], [0xff]])('round trips the key of every byte %i', (fill) => {
		const agentId = b64url(Buffer.alloc(32, fill));
		expect(agentIdFromDidKey(didOf(agentId))).toBe(agentId);
	});

	const id = VECTOR_IDS[0];
	const did = didOf(id);
	const body = Buffer.concat([MULTICODEC, keyBytes(id)]);
	it.each([
		[`did:key:z${base58(Buffer.concat([Buffer.from([0xe7, 0x01]), body.subarray(2)]))}`],
		[`did:key:z${base58(body.subarray(0, 33))}`],
		[`did:key:z${base58(Buffer.concat([body, Buffer.from([0])]))}`],
		[`did:key:z${base58(Buffer.concat([Buffer.from([0]), body]))}`],
		[`${did.slice(0, -1)}0`],
		[`did:key:f${did.slice('did:key:z'.length)}`],
		[did.replace('did:key:', 'did:web:')],
		[`${did}\n`],
		[id],
		[''],
		[`did:key:z6Mk${'2'.repeat(10_000 - 'did:key:z6Mk'.length)}`],
		[null],
	])('reads %j as no did:key', (value) => {
		expect(agentIdFromDidKey(value)).toBeNull();
	});
});
