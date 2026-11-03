// The gate, a pass or a block for an agent or a service before a call to it.

import type { Lookup } from './client';
import {
	BadTargetError,
	SealKeeperError,
	UnavailableError,
	hostLowered,
	isListedUrl,
} from './protocol';
import { SEAL_BROKEN_REASONS, type SubjectKind, type VerifiedSeal, cardUrlOf } from './seal';

// What a pass says. sealed is a current SEAL at bronze or above. The other
// three are a target with no SEAL let through by allow unsealed.
export const PASS_CODES = ['sealed', 'not_found', 'checking', 'no_seal'] as const;

// Every code a block can carry. The broken SEAL reasons come last.
export const BLOCK_CODES = [
	'unavailable',
	'bad_target',
	'error',
	'not_found',
	'checking',
	'no_seal',
	'withheld',
	'delisted',
	'unknown',
	'wrong_url',
	'wrong_kind',
	'below_bronze',
	...SEAL_BROKEN_REASONS,
] as const;

// Go ahead, with the verified SEAL, or null for a target let through
// unsealed, which code then names. Or do not call, with one line of why.
export type Decision =
	| { passed: true; code: string; seal: VerifiedSeal | null }
	| { passed: false; code: string; reason: string };

const pass = (code: string, seal: VerifiedSeal | null = null): Decision => ({
	passed: true,
	code,
	seal,
});
const block = (code: string, reason: string): Decision => ({ passed: false, code, reason });

const UNSEALED = new Set(['not_found', 'checking', 'no_seal']);

const REASONS: Record<string, string> = {
	not_found: 'SealKeeper knows no agent or service by that target',
	checking: 'SealKeeper is still checking it, so it holds no SEAL yet',
	no_seal: 'it holds no SEAL, it has been dormant',
	delisted: 'SealKeeper no longer lists it',
	unknown: 'it holds no SEAL and SealKeeper says nothing more',
	wrong_url: 'the SEAL is for another URL than the one asked for',
	below_bronze: 'its SEAL is below bronze',
};

// Each kind's SEAL as a reason names it.
const SEAL_NAMES: Record<SubjectKind, string> = {
	agent: 'an Agent SEAL',
	service: 'a Service SEAL',
};

// The decision for a lookup of target when kind is expected. A SEAL that
// verified must name the URL asked for when the target is a listed URL, be
// of kind and be bronze or above. Without a SEAL, only not_found, checking
// and no_seal pass, and only with allowUnsealed.
export function decide(
	target: string,
	kind: SubjectKind,
	lookup: Lookup,
	allowUnsealed: boolean,
): Decision {
	const seal = lookup.seal;
	if (seal !== null) {
		if (isListedUrl(target) && cardUrlOf(seal) !== hostLowered(target)) {
			return block('wrong_url', REASONS.wrong_url);
		}
		if (seal.kind !== kind) {
			return block('wrong_kind', `it holds ${SEAL_NAMES[seal.kind]}, not ${SEAL_NAMES[kind]}`);
		}
		if (seal.level === 'none') return block('below_bronze', REASONS.below_bronze);
		return pass('sealed', seal);
	}
	const code = lookup.code;
	if (code === 'broken' && lookup.broken !== null) {
		return block(lookup.broken, `broken SEAL: ${lookup.broken}`);
	}
	if (code !== null && UNSEALED.has(code)) {
		return allowUnsealed ? pass(code) : block(code, REASONS[code]);
	}
	if (code === 'withheld') {
		return block(
			'withheld',
			`SealKeeper withholds its SEAL, reason ${lookup.reason ?? 'no reason given'}`,
		);
	}
	if (code === 'delisted') return block('delisted', REASONS.delisted);
	return block('unknown', REASONS.unknown);
}

// The block for a lookup that threw.
export function blockOf(error: unknown): Decision {
	if (error instanceof BadTargetError) return block('bad_target', error.message);
	if (error instanceof UnavailableError) return block('unavailable', error.message);
	if (error instanceof SealKeeperError) return block('error', error.message);
	const name = error instanceof Error ? error.name : typeof error;
	return block('error', `unexpected ${name}`);
}
