// Verifying a SEAL offline, the steps of the SEAL Standard in their order.
// Every function here is pure. The client fetches the keys and calls
// verifyWithKeys with them.

import { createPublicKey, verify } from 'node:crypto';

// Every SEAL version this node reads. Any other ver is a broken SEAL.
export const SEAL_VERSIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const;

// Why a SEAL is broken, one per step of verification.
export const SEAL_BROKEN_REASONS = [
	'malformed',
	'unknown_kid',
	'bad_signature',
	'wrong_issuer',
	'unsupported_version',
	'expired',
	'not_yet_valid',
	'wrong_agent',
] as const;

export type SealBrokenReason = (typeof SEAL_BROKEN_REASONS)[number];

const ISSUER = 'sealkeeper.run';
// How far ahead of the clock iat may be before a SEAL is not yet valid.
const CLOCK_SKEW_SECONDS = 300;
// The longest a SEAL lives, from iat to exp.
const MAX_TTL_SECONDS = 24 * 3600;

export const LEVELS = ['none', 'bronze', 'silver', 'gold'] as const;
export const SUBJECT_KINDS = ['agent', 'service'] as const;
export type Level = (typeof LEVELS)[number];
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

const JWS_MAX_CHARS = 262144;
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const KID_MAX_UNITS = 128;
const B64URL = /^[A-Za-z0-9_-]*$/;
const KEYS_MAX = 16;

// An agent id, a raw 32 byte Ed25519 public key in base64url, 43
// characters. Only some last characters are canonical.
const AGENT_ID = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export const DID_KEY_PREFIX = 'did:key:z';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const DID_KEY = new RegExp(`^did:key:z6Mk[${BASE58}]{44}$`);

// A SEAL that checked out. Every field is read from the signed payload.
// kind is agent or service, level none, bronze, silver or gold. trust is
// the Trust Score, null before version 4. issuedAt and expiresAt are Unix
// seconds. payload is the payload as signed.
export interface VerifiedSeal {
	agentId: string;
	kind: SubjectKind;
	level: Level;
	trust: number | null;
	issuedAt: number;
	expiresAt: number;
	payload: Record<string, unknown>;
}

// What verifying a SEAL gives, the SEAL or the reason it is broken.
export type Verified = { seal: VerifiedSeal } | { broken: SealBrokenReason };

type JsonObject = Record<string, unknown>;

const broken = (reason: SealBrokenReason): Verified => ({ broken: reason });

export const isObject = (value: unknown): value is JsonObject =>
	typeof value === 'object' && value !== null && !Array.isArray(value);

// Whether the SEAL has not expired at now, Unix seconds.
export const isCurrent = (seal: VerifiedSeal, now: number): boolean =>
	Math.floor(seal.expiresAt - now) > 0;

export const b64urlEncode = (raw: Uint8Array): string => Buffer.from(raw).toString('base64url');

// Base64url with no padding, refusing any text that is not canonical. null
// for anything else.
export function b64urlDecode(text: string): Buffer | null {
	if (!B64URL.test(text) || text.length % 4 === 1) return null;
	const raw = Buffer.from(text, 'base64url');
	return b64urlEncode(raw) === text ? raw : null;
}

export const isAgentId = (value: unknown): value is string =>
	typeof value === 'string' && AGENT_ID.test(value);

// The agent id a did:key names, or null for anything else. The shape is
// checked first, so the base58 decode only ever reads 44 characters. The
// decode must give exactly 34 bytes, the ed25519-pub multicodec 0xed 0x01
// and then the key.
export function agentIdFromDidKey(did: unknown): string | null {
	if (typeof did !== 'string' || !DID_KEY.test(did)) return null;
	const body = did.slice(DID_KEY_PREFIX.length);
	const zeros = body.length - body.replace(/^1+/, '').length;
	let number = BigInt(0);
	for (const char of body) number = number * BigInt(58) + BigInt(BASE58.indexOf(char));
	let hex = number === BigInt(0) ? '' : number.toString(16);
	if (hex.length % 2 === 1) hex = `0${hex}`;
	const raw = Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex, 'hex')]);
	if (raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) return null;
	return b64urlEncode(raw.subarray(2));
}

// A kid's length is counted in UTF-16 code units, which is a string's
// length here.
const isKid = (kid: unknown): kid is string =>
	typeof kid === 'string' && kid.length >= 1 && kid.length <= KID_MAX_UNITS;

// The keys of a key document, kid to x, or null when it holds none. Only an
// Ed25519 key with a kid and a canonical x is kept, at most 16 read, and
// the first of a repeated kid wins.
export function readKeys(doc: unknown): Map<string, string> | null {
	if (!isObject(doc) || !Array.isArray(doc.keys)) return null;
	const keys = new Map<string, string>();
	for (const key of doc.keys.slice(0, KEYS_MAX)) {
		if (!isObject(key)) continue;
		const { kid, x } = key;
		if (
			key.kty === 'OKP' &&
			key.crv === 'Ed25519' &&
			key.alg === 'EdDSA' &&
			isKid(kid) &&
			isAgentId(x) &&
			!keys.has(kid)
		) {
			keys.set(kid, x);
		}
	}
	return keys.size > 0 ? keys : null;
}

const decoder = new TextDecoder('utf-8', { fatal: true });

// A base64url part read as JSON, or null when it is not. A leading byte
// order mark is dropped, as a web decoder does.
function jsonPart(part: string): { value: unknown } | null {
	const raw = b64urlDecode(part);
	if (raw === null) return null;
	try {
		return { value: JSON.parse(decoder.decode(raw)) };
	} catch {
		return null;
	}
}

function split(jws: string): [string, string, string] | null {
	if (jws.length > JWS_MAX_CHARS || !JWS.test(jws)) return null;
	const [header, payload, signature] = jws.split('.');
	return [header, payload, signature];
}

function kidOf(header: string): string | null {
	const parsed = jsonPart(header)?.value;
	if (
		!isObject(parsed) ||
		Object.keys(parsed).length !== 2 ||
		parsed.alg !== 'EdDSA' ||
		!isKid(parsed.kid)
	) {
		return null;
	}
	return parsed.kid;
}

// The kid a SEAL's header names, or null for a SEAL that is malformed.
export function sealKid(seal: unknown): string | null {
	if (typeof seal !== 'string') return null;
	const parts = split(seal.trim());
	return parts === null ? null : kidOf(parts[0]);
}

function signatureOk(x: string, header: string, payload: string, signature: string): boolean {
	const sig = b64urlDecode(signature);
	const publicKey = b64urlDecode(x);
	if (sig === null || publicKey === null || sig.length !== 64 || publicKey.length !== 32) {
		return false;
	}
	try {
		const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
		return verify(null, Buffer.from(`${header}.${payload}`, 'ascii'), key, sig);
	} catch {
		return false;
	}
}

// value as a whole number a JSON reader holds exactly, else null.
const whole = (value: unknown): number | null =>
	typeof value === 'number' && Number.isSafeInteger(value) ? value : null;

const has = (raw: JsonObject, name: string) => Object.prototype.hasOwnProperty.call(raw, name);

function listingOk(listing: unknown): boolean {
	if (!isObject(listing)) return false;
	const cardUrl = listing.card_url;
	return (
		typeof cardUrl === 'string' && (cardUrl.startsWith('http://') || cardUrl.startsWith('https://'))
	);
}

// The fields this node reads, each checked for its shape at ver. Only these
// are checked, so a payload with a bad field this node never reads still
// verifies here. null for a payload that is malformed.
function readFields(raw: JsonObject, ver: number): VerifiedSeal | null {
	const sub = raw.sub;
	const iat = whole(raw.iat);
	const exp = whole(raw.exp);
	const level = raw.level;
	if (
		!isAgentId(sub) ||
		iat === null ||
		exp === null ||
		iat < 0 ||
		!(iat < exp && exp <= iat + MAX_TTL_SECONDS) ||
		!LEVELS.includes(level as Level)
	) {
		return null;
	}
	// trust is in version 4 on, subject in version 7 on and listing in
	// version 5 on. A SEAL of an earlier version that carries one is
	// malformed, and one before version 7 is an agent's.
	let trust: number | null = null;
	if (ver >= 4) {
		trust = whole(raw.trust);
		if (trust === null || trust < 0) return null;
	} else if (has(raw, 'trust')) {
		return null;
	}
	let kind: unknown = 'agent';
	if (ver >= 7) {
		kind = isObject(raw.subject) ? raw.subject.kind : null;
		if (!SUBJECT_KINDS.includes(kind as SubjectKind)) return null;
	} else if (has(raw, 'subject')) {
		return null;
	}
	if (ver >= 5) {
		if (has(raw, 'listing') && !listingOk(raw.listing)) return null;
	} else if (has(raw, 'listing')) {
		return null;
	}
	return {
		agentId: sub,
		kind: kind as SubjectKind,
		level: level as Level,
		trust,
		issuedAt: iat,
		expiresAt: exp,
		payload: raw,
	};
}

function checkPayload(raw: unknown, now: number, agent: string): Verified {
	if (!isObject(raw) || raw.iss !== ISSUER) return broken('wrong_issuer');
	const ver = whole(raw.ver);
	if (ver === null || !(SEAL_VERSIONS as readonly number[]).includes(ver)) {
		return broken('unsupported_version');
	}
	const seal = readFields(raw, ver);
	if (seal === null) return broken('malformed');
	if (!isCurrent(seal, now)) return broken('expired');
	if (seal.issuedAt - now > CLOCK_SKEW_SECONDS) return broken('not_yet_valid');
	if (seal.agentId !== agent) return broken('wrong_agent');
	return { seal };
}

// Verifies a SEAL against keys, kid to x, at now, Unix seconds. The steps
// of the standard in order. The header, the key its kid names, the
// signature over the exact header.payload bytes and only then the payload
// as JSON, the issuer, the version and the shape, exp then iat, and last
// sub against agent, the agent id the caller expects. Answers the reason
// of the first step that fails.
export function verifyWithKeys(
	seal: unknown,
	keys: ReadonlyMap<string, string>,
	now: number,
	agent: string,
): Verified {
	if (typeof seal !== 'string') return broken('malformed');
	const parts = split(seal.trim());
	if (parts === null) return broken('malformed');
	const [header, payload, signature] = parts;
	const kid = kidOf(header);
	if (kid === null) return broken('malformed');
	const x = keys.get(kid);
	if (x === undefined) return broken('unknown_kid');
	if (!signatureOk(x, header, payload, signature)) return broken('bad_signature');
	const raw = jsonPart(payload);
	if (raw === null) return broken('malformed');
	return checkPayload(raw.value, now, agent);
}

// The card URL a listed SEAL names, null for a SEAL with no listing.
export function cardUrlOf(seal: VerifiedSeal): string | null {
	const listing = seal.payload.listing;
	return isObject(listing) && typeof listing.card_url === 'string' ? listing.card_url : null;
}
