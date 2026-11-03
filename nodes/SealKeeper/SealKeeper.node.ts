import type {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError, sleep } from 'n8n-workflow';

import { type Io, type Lookup, lookUp, sendWith } from './client';
import { type Decision, blockOf, decide } from './gate';
import { KeyCache } from './protocol';
import { isCurrent } from './seal';

// The copy of SealKeeper's keys, shared by every run of the node in this
// n8n process. A copy is used for five minutes and fetched again for a kid
// it does not know.
const KEY_CACHE = new KeyCache();

const MAIN = NodeConnectionTypes.Main;

const iso = (seconds: number): string => new Date(seconds * 1000).toISOString();

const messageOf = (error: unknown): string =>
	error instanceof Error ? error.message : 'the lookup failed';

// The answer of a lookup this version cannot read, without its agent part.
// SealKeeper does not sign that part, so its level, kind and Trust Score
// never reach an item.
function rawJson(raw: Record<string, unknown> | null): IDataObject | null {
	if (raw === null) return null;
	const rest: IDataObject = { ...(raw as IDataObject) };
	delete rest.agent;
	return rest;
}

// A lookup as one output item. Level, kind and Trust Score are read from
// the verified SEAL only, so they are null unless it verified.
function lookupJson(target: string, lookup: Lookup): IDataObject {
	const seal = lookup.seal;
	return {
		target,
		verified: seal !== null,
		status: lookup.status,
		code: lookup.code,
		kind: seal?.kind ?? null,
		level: seal?.level ?? null,
		trust: seal?.trust ?? null,
		agentId: seal?.agentId ?? null,
		issuedAt: seal === null ? null : iso(seal.issuedAt),
		expiresAt: seal === null ? null : iso(seal.expiresAt),
		broken: lookup.broken,
		reason: lookup.reason,
		since: lookup.since,
		dormantDays: lookup.dormantDays,
		handle: lookup.handle,
		raw: rawJson(lookup.raw),
	};
}

// A decision as one output item. A pass on a SEAL carries its level, Trust
// Score, agent id and expiry. A block carries only its code and reason.
function decisionJson(target: string, kind: string, decision: Decision): IDataObject {
	const seal = decision.passed ? decision.seal : null;
	return {
		target,
		kind,
		passed: decision.passed,
		code: decision.code,
		reason: decision.passed ? null : decision.reason,
		level: seal?.level ?? null,
		trust: seal?.trust ?? null,
		agentId: seal?.agentId ?? null,
		expiresAt: seal === null ? null : iso(seal.expiresAt),
	};
}

export class SealKeeper implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'SealKeeper',
		name: 'sealKeeper',
		icon: { light: 'file:sealkeeper.svg', dark: 'file:sealkeeper.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] === "check" ? "Check" : "Look up"}}',
		description:
			'Look up an AI agent or service on SealKeeper and verify its SEAL, or check it before a call',
		defaults: {
			name: 'SealKeeper',
		},
		usableAsTool: true,
		inputs: [MAIN],
		outputs: `={{$parameter["operation"] === "check" ? [{ "type": "${MAIN}", "displayName": "Pass" }, { "type": "${MAIN}", "displayName": "Block" }] : ["${MAIN}"]}}`,
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Check',
						value: 'check',
						description:
							'Pass a target that holds a current SEAL of the kind at bronze or above, and block the rest',
						action: 'Check an agent or service before a call',
					},
					{
						name: 'Look Up',
						value: 'lookUp',
						description: 'Read the SEAL of an agent or service and verify it on this machine',
						action: 'Look up the SEAL of an agent or service',
					},
				],
				default: 'lookUp',
			},
			{
				displayName: 'Target',
				name: 'target',
				type: 'string',
				required: true,
				default: '',
				placeholder: 'https://mcp.example.com/mcp',
				description:
					'A SealKeeper handle such as alice/helper, a SealKeeper page URL, an agent ID, a did:key, an A2A agent card URL or an MCP server URL',
			},
			{
				displayName: 'Kind',
				name: 'kind',
				type: 'options',
				options: [
					{
						name: 'Agent',
						value: 'agent',
						description: 'An AI agent, such as a remote A2A agent',
					},
					{
						name: 'Service',
						value: 'service',
						description: 'A service, such as an MCP server',
					},
				],
				default: 'service',
				description: 'The kind of SEAL the target must hold',
				displayOptions: {
					show: {
						operation: ['check'],
					},
				},
			},
			{
				displayName: 'Allow Unsealed',
				name: 'allowUnsealed',
				type: 'boolean',
				default: false,
				description:
					'Whether to also pass a target SealKeeper does not know, is still checking or holds no SEAL for while it is dormant',
				displayOptions: {
					show: {
						operation: ['check'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const operation = this.getNodeParameter('operation', 0) as string;
		// As an AI agent tool the node has one output, which the agent reads,
		// so a check answers every decision there.
		const asTool = this.getNode().type.endsWith('Tool');
		const io: Io = {
			send: sendWith(async (options) => await this.helpers.httpRequest(options)),
			sleep,
			now: () => Date.now() / 1000,
			keys: KEY_CACHE,
		};

		// One lookup per target in a run. A failed lookup is never kept, and a
		// kept SEAL is checked against its expiry on every use.
		const found = new Map<string, Lookup>();
		const lookUpOnce = async (target: string): Promise<Lookup> => {
			const kept = found.get(target);
			if (kept !== undefined && (kept.seal === null || isCurrent(kept.seal, io.now()))) {
				return kept;
			}
			const lookup = await lookUp(io, target);
			found.set(target, lookup);
			return lookup;
		};

		if (operation === 'check') {
			const passed: INodeExecutionData[] = [];
			const blocked: INodeExecutionData[] = [];
			for (let i = 0; i < items.length; i++) {
				let target = '';
				let kind = '';
				let decision: Decision;
				try {
					target = this.getNodeParameter('target', i) as string;
					kind = this.getNodeParameter('kind', i) as string;
					const allowUnsealed = this.getNodeParameter('allowUnsealed', i, false) as boolean;
					if (kind !== 'agent' && kind !== 'service') {
						throw new NodeOperationError(this.getNode(), 'Kind must be agent or service');
					}
					try {
						decision = decide(target, kind, await lookUpOnce(target), allowUnsealed);
					} catch (error) {
						decision = blockOf(error);
					}
				} catch (error) {
					// n8n sends the input of a node that throws to its first output,
					// Pass, when On Error continues. So a parameter error blocks then.
					if (!this.continueOnFail()) {
						throw new NodeOperationError(this.getNode(), messageOf(error), { itemIndex: i });
					}
					decision = { passed: false, code: 'error', reason: messageOf(error) };
				}
				const output = decision.passed || asTool ? passed : blocked;
				output.push({ json: decisionJson(target, kind, decision), pairedItem: { item: i } });
			}
			return asTool ? [passed] : [passed, blocked];
		}

		const returnData: INodeExecutionData[] = [];
		for (let i = 0; i < items.length; i++) {
			try {
				const target = this.getNodeParameter('target', i) as string;
				const lookup = await lookUpOnce(target);
				returnData.push({ json: lookupJson(target, lookup), pairedItem: { item: i } });
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: messageOf(error) }, pairedItem: { item: i } });
					continue;
				}
				throw new NodeOperationError(this.getNode(), messageOf(error), { itemIndex: i });
			}
		}
		return [returnData];
	}
}
