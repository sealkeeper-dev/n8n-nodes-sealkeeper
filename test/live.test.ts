// Against production, only with SEALKEEPER_LIVE=1. Read only.

import type { IHttpRequestOptions } from 'n8n-workflow';
import { describe, expect, inject, it } from 'vitest';

import { type Io, lookUp, sendWith, verify } from '../nodes/SealKeeper/client';
import { KeyCache, MCP_URL, mcpHeaders, readAnswer, toolCall } from '../nodes/SealKeeper/protocol';
import { b64url } from './support';

declare module 'vitest' {
	export interface ProvidedContext {
		live: boolean;
	}
}

// n8n's request helper for the options the node sends, over fetch.
async function httpRequest(options: IHttpRequestOptions): Promise<unknown> {
	const response = await fetch(options.url, {
		method: options.method,
		headers: options.headers as Record<string, string>,
		body: options.body as string | undefined,
		redirect: 'manual',
		signal: options.abortSignal as AbortSignal,
	});
	return {
		statusCode: response.status,
		headers: Object.fromEntries(response.headers),
		body: Buffer.from(await response.arrayBuffer()),
	};
}

function flipSignature(seal: string): string {
	const [head, body, sig] = seal.split('.');
	const raw = Buffer.from(sig, 'base64url');
	raw[0] ^= 1;
	return `${head}.${body}.${b64url(raw)}`;
}

describe.skipIf(!inject('live'))('production', () => {
	it('verifies the test agent SEAL, and one changed byte breaks it', async () => {
		const io: Io = {
			send: sendWith(httpRequest),
			sleep: async () => {},
			now: () => Date.now() / 1000,
			keys: new KeyCache(),
		};
		const found = await lookUp(io, 'sealkeeper/test-agent');
		expect([found.seal?.kind, found.seal?.level]).toEqual(['agent', 'none']);
		const agentId = found.seal?.agentId as string;
		const sent = await io.send(
			'POST',
			MCP_URL,
			toolCall('get_trust', { agent: 'sealkeeper/test-agent' }),
			mcpHeaders(),
		);
		const seal = readAnswer(sent.status, sent.body).seal as string;
		const good = await verify(io, seal, agentId);
		expect('seal' in good && good.seal.agentId).toBe(agentId);
		expect(await verify(io, flipSignature(seal), agentId)).toEqual({ broken: 'bad_signature' });
	});
});
