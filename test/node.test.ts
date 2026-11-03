// The node, run the way n8n runs it, with a pinned clock and a recorded
// SealKeeper behind n8n's request helper.

import type {
	IExecuteFunctions,
	IHttpRequestOptions,
	INode,
	INodeExecutionData,
} from 'n8n-workflow';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import README from '../README.md?raw';
import pkg from '../package.json';

import type { SealKeeper as SealKeeperNode } from '../nodes/SealKeeper/SealKeeper.node';
import {
	FIXTURE_AGENT,
	KEYS_URL,
	PINNED,
	Server,
	answer,
	payloadOf,
	reply,
	sealFile,
	trust,
} from './support';

const AGENT_SEAL = sealFile('v7-valid');
const SERVICE_SEAL = sealFile('v7-service-valid');
const NOT_FOUND = trust('not_found', null, null);
const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

type Params = Record<string, unknown>;

interface Run {
	asTool?: boolean;
	continueOnFail?: boolean;
}

let node: SealKeeperNode;

// A fresh copy of the node's module, so each test starts with no keys.
beforeEach(async () => {
	vi.resetModules();
	vi.useFakeTimers({ toFake: ['Date'] });
	vi.setSystemTime(PINNED * 1000);
	const { SealKeeper } = await import('../nodes/SealKeeper/SealKeeper.node');
	node = new SealKeeper();
});

afterEach(() => {
	vi.useRealTimers();
});

// Runs the node once over one input item per entry of items, each entry
// the parameters of that item.
async function execute(
	server: Server | ((options: IHttpRequestOptions) => Promise<unknown>),
	items: Params[],
	run: Run = {},
): Promise<INodeExecutionData[][]> {
	const httpRequest = server instanceof Server ? server.httpRequest : server;
	const context = {
		getInputData: () => items.map(() => ({ json: {} })),
		getNodeParameter: (name: string, index: number, fallback?: unknown) =>
			items[index]?.[name] ?? fallback,
		getNode: () => ({
			id: 'node-1',
			name: 'SealKeeper',
			type: run.asTool ? 'n8n-nodes-sealkeeper.sealKeeperTool' : 'n8n-nodes-sealkeeper.sealKeeper',
			typeVersion: 1,
			position: [0, 0],
			parameters: {},
		}),
		continueOnFail: () => run.continueOnFail ?? false,
		helpers: { httpRequest },
	};
	return await node.execute.call(context as unknown as IExecuteFunctions);
}

const lookUpItem = (target: string): Params => ({ operation: 'lookUp', target });
const checkItem = (target: string, kind = 'agent', allowUnsealed = false): Params => ({
	operation: 'check',
	target,
	kind,
	allowUnsealed,
});

describe('the description', () => {
	it('is one node with two operations, usable as a tool', () => {
		const { description } = node;
		expect([description.name, description.displayName, description.version]).toEqual([
			'sealKeeper',
			'SealKeeper',
			1,
		]);
		expect(description.usableAsTool).toBe(true);
		const operation = description.properties.find((p) => p.name === 'operation');
		expect(operation?.default).toBe('lookUp');
		expect(operation?.options?.map((o) => ('value' in o ? o.value : null))).toEqual([
			'check',
			'lookUp',
		]);
		expect(description.properties.map((p) => p.name)).toEqual([
			'operation',
			'target',
			'kind',
			'allowUnsealed',
		]);
	});

	// n8n reads an operation's action as the tool description only under a
	// resource, so both operations take the node's description.
	it.each([['check'], ['lookUp']])(
		'describes the %s tool with both operations',
		async (operation) => {
			const tool = {
				parameters: { operation, descriptionType: 'auto' },
			} as unknown as INode;
			const { NodeHelpers } = await import('n8n-workflow');
			expect(NodeHelpers.getToolDescriptionForNode(tool, node)).toBe(
				'Look up an AI agent or service on SealKeeper and verify its SEAL, or check it before a call',
			);
		},
	);

	it('names every target form in the Target help', () => {
		const help = node.description.properties.find((p) => p.name === 'target')?.description;
		for (const form of [
			'handle',
			'page URL',
			'agent ID',
			'did:key',
			'card URL',
			'MCP server URL',
		]) {
			expect(help).toContain(form);
		}
	});

	it('draws Pass and Block outputs for a check only', () => {
		const outputs = node.description.outputs as string;
		expect(outputs).toMatch(/^=\{\{\$parameter\["operation"\] === "check" \?/);
		expect(outputs).toContain('"displayName": "Pass"');
		expect(outputs).toContain('"displayName": "Block"');
	});
});

describe('Look Up', () => {
	it('answers one item per input with the verified SEAL', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL))]);
		const out = await execute(server, [lookUpItem('alice/fixture')]);
		const payload = payloadOf(AGENT_SEAL);
		expect(out).toEqual([
			[
				{
					json: {
						target: 'alice/fixture',
						verified: true,
						status: 'shown',
						code: null,
						kind: 'agent',
						level: 'bronze',
						trust: 412,
						agentId: FIXTURE_AGENT.id,
						issuedAt: iso(payload.iat as number),
						expiresAt: iso(payload.exp as number),
						broken: null,
						reason: null,
						since: null,
						dormantDays: null,
						handle: 'alice/fixture',
						raw: null,
					},
					pairedItem: { item: 0 },
				},
			],
		]);
	});

	it('answers no level, kind or Trust Score without a verified SEAL', async () => {
		const server = new Server([answer(trust('shown', sealFile('v1-bad-signature')))]);
		const [[item]] = await execute(server, [lookUpItem('alice/fixture')]);
		expect(item.json).toMatchObject({
			verified: false,
			code: 'broken',
			broken: 'bad_signature',
			kind: null,
			level: null,
			trust: null,
			agentId: null,
		});
	});

	it('answers withheld with its reason and since', async () => {
		const since = '2026-10-30T08:00:00.000Z';
		const data = trust('shown', null, undefined, {
			withheld: { code: 'withheld', reason: 'fraud', since },
		});
		const [[item]] = await execute(new Server([answer(data)]), [lookUpItem('alice/fixture')]);
		expect(item.json).toMatchObject({ verified: false, code: 'withheld', reason: 'fraud', since });
	});

	// The agent part of an answer is unsigned, so its level, kind and Trust
	// Score never reach an item, raw included.
	it('answers an unknown answer in raw without its agent part', async () => {
		const agent = { id: FIXTURE_AGENT.id, handle: 'alice/fixture', level: 'gold', trust: 900 };
		const data = trust('shown', null, { ...agent, subjectKind: 'service' });
		const [[item]] = await execute(new Server([answer(data)]), [lookUpItem('alice/fixture')]);
		expect(item.json).toMatchObject({
			verified: false,
			code: 'unknown',
			kind: null,
			level: null,
			trust: null,
			handle: 'alice/fixture',
			raw: { skill: 'get-trust', status: 'shown', seal: null },
		});
		expect(item.json.raw).not.toHaveProperty('agent');
		expect(JSON.stringify(item.json)).not.toMatch(/gold|900/);
	});

	it('throws a node error naming the item when SealKeeper is unavailable', async () => {
		const server = new Server([reply(503, Buffer.alloc(0))]);
		const run = execute(server, [lookUpItem('alice/fixture')]);
		await expect(run).rejects.toMatchObject({
			name: 'NodeOperationError',
			message: 'SealKeeper answered HTTP 503',
			context: { itemIndex: 0 },
		});
	});

	it('answers the error as an item when the workflow continues on fail', async () => {
		const server = new Server([reply(503, Buffer.alloc(0)), answer(NOT_FOUND)]);
		const out = await execute(server, [lookUpItem('alice/one'), lookUpItem('alice/two')], {
			continueOnFail: true,
		});
		expect(out[0].map((item) => [item.json.error ?? item.json.code, item.pairedItem])).toEqual([
			['SealKeeper answered HTTP 503', { item: 0 }],
			['not_found', { item: 1 }],
		]);
	});
});

describe('Check', () => {
	it('routes each item to Pass or Block', async () => {
		const server = new Server([
			answer(trust('shown', AGENT_SEAL)),
			answer(NOT_FOUND),
			answer(trust('shown', SERVICE_SEAL)),
		]);
		const [passed, blocked] = await execute(server, [
			checkItem('alice/one'),
			checkItem('alice/two'),
			checkItem('alice/three', 'service'),
		]);
		expect(passed.map((item) => [item.json.target, item.pairedItem])).toEqual([
			['alice/one', { item: 0 }],
			['alice/three', { item: 2 }],
		]);
		expect(blocked.map((item) => [item.json.target, item.pairedItem])).toEqual([
			['alice/two', { item: 1 }],
		]);
	});

	it('answers a pass with the SEAL and a block with its code and reason', async () => {
		const server = new Server([
			answer(trust('shown', AGENT_SEAL)),
			answer(trust('shown', SERVICE_SEAL)),
		]);
		const [[passed], [blocked]] = await execute(server, [
			checkItem('alice/one', 'agent'),
			checkItem('alice/two', 'agent'),
		]);
		expect(passed.json).toEqual({
			target: 'alice/one',
			kind: 'agent',
			passed: true,
			code: 'sealed',
			reason: null,
			level: 'bronze',
			trust: 412,
			agentId: FIXTURE_AGENT.id,
			expiresAt: iso(payloadOf(AGENT_SEAL).exp as number),
		});
		expect(blocked.json).toEqual({
			target: 'alice/two',
			kind: 'agent',
			passed: false,
			code: 'wrong_kind',
			reason: 'it holds a Service SEAL, not an Agent SEAL',
			level: null,
			trust: null,
			agentId: null,
			expiresAt: null,
		});
	});

	it('passes a target SealKeeper does not know only with Allow Unsealed', async () => {
		const blocked = await execute(new Server([answer(NOT_FOUND)]), [checkItem('alice/new')]);
		expect([blocked[0].length, blocked[1][0].json.code]).toEqual([0, 'not_found']);
		const allowed = await execute(new Server([answer(NOT_FOUND)]), [
			checkItem('alice/new', 'agent', true),
		]);
		expect([allowed[0][0].json.passed, allowed[0][0].json.code, allowed[1].length]).toEqual([
			true,
			'not_found',
			0,
		]);
	});

	it('blocks when SealKeeper is unavailable and never throws', async () => {
		const [passed, blocked] = await execute(new Server([reply(503, Buffer.alloc(0))]), [
			checkItem('alice/fixture', 'agent', true),
		]);
		expect(passed).toEqual([]);
		expect(blocked[0].json).toMatchObject({ passed: false, code: 'unavailable' });
	});

	it('answers every decision on the one output as an AI agent tool', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL)), answer(NOT_FOUND)]);
		const out = await execute(server, [checkItem('alice/one'), checkItem('alice/two')], {
			asTool: true,
		});
		expect(out).toHaveLength(1);
		expect(out[0].map((item) => [item.json.passed, item.json.code])).toEqual([
			[true, 'sealed'],
			[false, 'not_found'],
		]);
	});

	it('throws for a kind other than agent or service', async () => {
		const run = execute(new Server([answer(NOT_FOUND)]), [checkItem('alice/one', 'robot')]);
		await expect(run).rejects.toMatchObject({
			name: 'NodeOperationError',
			message: 'Kind must be agent or service',
			context: { itemIndex: 0 },
		});
	});

	// n8n sends the input of a node that throws to Pass when On Error
	// continues, so the node blocks the item itself.
	it('blocks a kind other than agent or service when the workflow continues on fail', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL))]);
		const [passed, blocked] = await execute(
			server,
			[checkItem('alice/one', 'robot'), checkItem('alice/two')],
			{ continueOnFail: true },
		);
		expect(passed.map((item) => [item.json.code, item.pairedItem])).toEqual([
			['sealed', { item: 1 }],
		]);
		expect(blocked).toEqual([
			{
				json: {
					target: 'alice/one',
					kind: 'robot',
					passed: false,
					code: 'error',
					reason: 'Kind must be agent or service',
					level: null,
					trust: null,
					agentId: null,
					expiresAt: null,
				},
				pairedItem: { item: 0 },
			},
		]);
	});
});

describe('one run', () => {
	it('looks each target up once, and a new run looks it up again', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL))]);
		await execute(server, [checkItem('alice/one'), checkItem('alice/one', 'service')]);
		await execute(server, [lookUpItem('alice/one'), lookUpItem('alice/one')]);
		expect(server.calls()).toHaveLength(2);
	});

	it('keeps no failed lookup', async () => {
		const server = new Server([reply(503, Buffer.alloc(0)), answer(trust('shown', AGENT_SEAL))]);
		const [passed, blocked] = await execute(server, [
			checkItem('alice/one'),
			checkItem('alice/one'),
		]);
		expect([blocked[0].json.code, passed[0].json.code]).toEqual(['unavailable', 'sealed']);
		expect(server.calls()).toHaveLength(2);
	});

	it('checks a kept SEAL against its expiry on every use', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL))]);
		const exp = payloadOf(AGENT_SEAL).exp as number;
		// The clock moves to the SEAL's expiry once the first answer is in.
		const moving = async (options: IHttpRequestOptions) => {
			const response = await server.httpRequest(options);
			if (options.url === KEYS_URL) vi.setSystemTime(exp * 1000);
			return response;
		};
		const [passed, blocked] = await execute(moving, [
			checkItem('alice/one'),
			checkItem('alice/one'),
		]);
		expect([passed[0].json.code, blocked[0].json.code]).toEqual(['sealed', 'expired']);
		expect(server.calls()).toHaveLength(2);
	});
});

describe('the key copy', () => {
	it('is kept across runs for five minutes', async () => {
		const server = new Server([answer(trust('shown', AGENT_SEAL))]);
		await execute(server, [lookUpItem('alice/fixture')]);
		vi.setSystemTime((PINNED + 299) * 1000);
		await execute(server, [lookUpItem('alice/fixture')]);
		expect(server.of(KEYS_URL)).toHaveLength(1);
		vi.setSystemTime((PINNED + 300) * 1000);
		await execute(server, [lookUpItem('alice/fixture')]);
		expect(server.of(KEYS_URL)).toHaveLength(2);
	});
});

describe('the README example workflow', () => {
	const workflowOf = () => {
		const block = README.split('## Example workflow')[1]?.match(/```json\n([\s\S]*?)\n```/)?.[1];
		return JSON.parse(block ?? 'null') as {
			nodes: { name: string; type: string; typeVersion: number; parameters: Params }[];
			connections: Record<string, { main: { node: string }[][] }>;
		};
	};

	it('uses this node with values its parameters take', () => {
		const { nodes } = workflowOf();
		const ours = nodes.filter((n) => n.type === `${pkg.name}.${node.description.name}`);
		expect(ours).toHaveLength(1);
		const [check] = ours;
		expect(check.typeVersion).toBe(node.description.version);
		for (const [name, value] of Object.entries(check.parameters)) {
			const property = node.description.properties.find((p) => p.name === name);
			expect(property, name).toBeDefined();
			const values = property?.options?.map((o) => ('value' in o ? o.value : null));
			if (values) expect(values, name).toContain(value);
		}
		expect(check.parameters.operation).toBe('check');
	});

	it('wires Pass to the call and Block to its own node', () => {
		const { nodes, connections } = workflowOf();
		const check = nodes.find((n) => n.type.endsWith(`.${node.description.name}`));
		const [pass, block] = connections[check?.name ?? ''].main;
		const typeOf = (name: string | undefined) => nodes.find((n) => n.name === name)?.type;
		expect(typeOf(pass[0]?.node)).toBe('@n8n/n8n-nodes-langchain.mcpClient');
		expect(typeOf(block[0]?.node)).toBe('n8n-nodes-base.noOp');
	});
});
