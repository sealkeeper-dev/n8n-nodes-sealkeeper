# n8n-nodes-sealkeeper

Look up an AI agent or an MCP server on [SealKeeper](https://sealkeeper.run), verify its SEAL inside n8n and route your workflow on it.

A SEAL is SealKeeper's signed credential. The node checks it against SealKeeper's public keys, so what you act on is what SealKeeper signed. An Agent SEAL is for an AI agent, a Service SEAL for a service such as an MCP server.

## Install

1. In n8n, open **Settings** > **Community Nodes** and select **Install**.
2. Enter `n8n-nodes-sealkeeper`, accept the risk note and select **Install**.

An owner or an admin installs it. It needs no credentials and no other package.

To check an MCP server or an A2A agent by its URL, copy the URL from its page on SealKeeper. Only that exact URL finds it.

## Look Up

Set **Operation** to **Look Up** and **Target** to a handle, a SealKeeper page URL, an agent id, a `did:key`, an A2A card URL or an MCP server URL. Each input item gives one item.

```json
{
  "target": "aibenchmarkindex.com/ai-benchmark-index",
  "verified": true,
  "status": "shown",
  "code": null,
  "kind": "agent",
  "level": "bronze",
  "trust": 200,
  "agentId": "7yehMLp2oIbBmZnWwskNW42bJyjEMEjPjlmIlMpm0kI",
  "issuedAt": "2026-11-02T06:37:35.000Z",
  "expiresAt": "2026-11-03T06:37:35.000Z",
  "broken": null,
  "reason": null,
  "since": null,
  "dormantDays": null,
  "handle": "aibenchmarkindex.com/ai-benchmark-index",
  "raw": null
}
```

`kind`, `level` and `trust` come from the SEAL only after it verifies. Without one they are `null`, and `code` says why.

| `code` | Meaning |
|---|---|
| `broken` | The SEAL did not verify. `broken` holds the reason |
| `withheld` | SealKeeper withholds the SEAL. `reason` and `since` say why and from when |
| `no_seal` | No SEAL while the agent is dormant. `dormantDays` says how long |
| `checking` | SealKeeper is still checking it |
| `delisted` | SealKeeper no longer lists it |
| `not_found` | The target names no agent or service |
| `unknown` | No SEAL, and the answer says nothing more. `raw` holds the answer without its unsigned agent part |

## Check

Set **Operation** to **Check**, **Kind** to **Agent** or **Service** and **Target** to what the workflow calls next. Each item goes to the **Pass** or the **Block** output.

For an MCP server, such as `https://stoop-mcp-server.stoop.workers.dev/mcp` with **Kind** set to **Service**, connect Pass to an MCP Client node with the same **MCP Endpoint URL**. This is the input of its `service_search` tool, with **Input Mode** set to **JSON**.

```json
{
  "query": "need a plumber for a leak",
  "location": "Miami, FL"
}
```

A blocked item carries the code and the reason.

```json
{
  "target": "https://stoop-mcp-server.stoop.workers.dev/mcp/",
  "kind": "service",
  "passed": false,
  "code": "not_found",
  "reason": "SealKeeper knows no agent or service by that target",
  "level": null,
  "trust": null,
  "agentId": null,
  "expiresAt": null
}
```

To see one, add a trailing `/` to **Target**, as above.

For a remote A2A agent, such as `https://aibenchmarkindex.com/.well-known/agent-card.json` with **Kind** set to **Agent**, connect Pass to an HTTP Request node that POSTs to the `url` of the card, `https://aibenchmarkindex.com/a2a`, with this JSON body.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "message/send",
  "params": {
    "message": {
      "kind": "message",
      "messageId": "{{ $execution.id }}",
      "role": "user",
      "parts": [{ "kind": "text", "text": "List benchmarks in the Coding category." }]
    }
  }
}
```

A pass needs a current, valid SEAL of the kind at bronze or above. For a card or MCP server URL, the SEAL must name that URL.

| Block `code` | Why |
|---|---|
| `wrong_url` | The SEAL names another URL |
| `wrong_kind` | The SEAL is of the other kind |
| `below_bronze` | The SEAL is at level none |
| `not_found`, `checking`, `no_seal` | No SEAL. **Allow Unsealed** passes these |
| `withheld`, `delisted`, `unknown` | No SEAL, and these always block |
| `unavailable` | SealKeeper did not answer |
| `bad_target`, `error` | SealKeeper refused the target or answered something else |
| `malformed`, `unknown_kid`, `bad_signature`, `wrong_issuer`, `unsupported_version`, `expired`, `not_yet_valid`, `wrong_agent` | The SEAL did not verify |

A pass says `sealed`, or the code **Allow Unsealed** let through. Check stops the workflow only for a parameter error, such as a **Kind** that is not agent or service. With **On Error** set to continue, that item goes to Block as `error`.

## As an AI agent tool

Add SealKeeper as a tool of an AI Agent node and select the star at the end of **Target**, so the model sets it. As a tool, Check answers every decision as one item, with `passed` true or false.

For Check, set **Tool Description** to **Set Manually** and tell the model what `passed` means, such as `Checks an AI agent or service on SealKeeper before a call. Call it only when passed is true.`

## Good to know

- A run looks each target up once. The node keeps SealKeeper's keys for 5 minutes.
- It verifies the fields it reads and returns, `sub`, `iat`, `exp`, `level`, `trust`, `subject.kind` and `listing.card_url`. It is not a full conformance reader of the [SEAL Standard](https://sealkeeper.run/seal/standard).
- A SEAL is not a permission.

More at [sealkeeper.run/docs/n8n](https://sealkeeper.run/docs/n8n).

## Licence

MIT
