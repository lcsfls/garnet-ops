# AI triage

GarnetOps can discuss every finding with **your own model**: vLLM, Ollama, LiteLLM, LM Studio
or anything else that speaks the OpenAI API. The first answer is a short, structured triage
(is it exploitable, is it probably reachable, what to do); after that you can ask follow-up
questions. Design and threat model: ADR 0013.

AI is optional and **off until you switch it on**. Scans, quality gates and notifications
never depend on it.

## What is sent to the model

For the conversation about one finding:

- the vulnerability: id, aliases, severity, CVSS score and vector, EPSS, whether it is known
  to be exploited, dates, and the advisory text;
- the package: name, installed version, ecosystem, the versions that fix it, and the paths
  inside the repository where it was found;
- the repository name and branch;
- how many other repositories and servers have the same vulnerability (numbers only);
- your questions, and the earlier answers of the same conversation.

Under **What the model saw** in every conversation you can read exactly what was sent,
including the fixed instructions.

## What is never sent

Passwords, tokens, keys and deploy keys, repository URLs, user names and e-mail addresses,
and **source code**: GarnetOps keeps no clones, so the model reasons from metadata only and
answers "unknown" when reachability depends on code it cannot see. Anything that looks like
a credential in scanned text is removed before sending, as a second line of defence.

## Set up (owners and admins)

1. Start your model server and note its OpenAI-compatible address.
2. **Settings → AI**: enter the **server address**, press **Load models** (optional) and
   choose the **model**, enter an **API key** if the server wants one, press **Test
   connection**, switch **Switch AI triage on** and **Save**. Saving, removing and testing
   need a sign-in from the last ten minutes.

Examples (`llm.example.lan` stands for your own server behind a reverse proxy with a
certificate, `ollama` for a service next to GarnetOps, `100.64.0.20` for a server in your VPN):

| Where the model runs | Address | Notes |
| --- | --- | --- |
| Another machine on your network, behind a reverse proxy with https | `https://llm.example.lan/v1` | the proxy terminates TLS (see below); the model server itself listens only on the proxy's side |
| A service on the same host, next to the worker (Docker Compose) | `http://ollama:11434/v1` | plain http is fine: the traffic stays on the Docker network (see below) |
| A server in your VPN (NetBird, Tailscale) | `http://100.64.0.20:11434/v1` | the overlay encrypts the traffic itself |
| LiteLLM proxy, vLLM, LM Studio | the same three patterns | vLLM: `vllm serve <model>`, add `--api-key` if you want a key; LM Studio: "Serve on Local Network"; LiteLLM: the key is the proxy's master or virtual key |

For Ollama the model name is the one `ollama list` shows; on another machine set
`OLLAMA_HOST` so that it listens where the reverse proxy or the VPN can reach it.

Code models from about 14 B parameters triage reliably. Smaller ones explain well and judge
reachability poorly. Reasoning models work: their `<think>` blocks are hidden.

### Where the model may run

| Model server address | Allowed |
| --- | --- |
| **Same host or same Docker network as the worker**: the address lies inside a subnet of one of the worker's own network interfaces (a Compose service such as `http://ollama:11434/v1`, or the Docker host through the bridge gateway) | `http://` or `https://` |
| **VPN overlay 100.64.0.0/10** (NetBird, Tailscale), also written as an IPv4-mapped address | `http://` or `https://` |
| **Other private addresses**: 10.x, 172.16-31.x, 192.168.x, fc00::/7 | `https://` only |
| **Public addresses** | `https://` only, plus your confirmation (below) |
| Loopback, link-local, unspecified, multicast, reserved | never |

Why not plain http on your LAN? The request contains the list of vulnerabilities of your
repositories and servers. Over http, anyone who can sniff or ARP-spoof on that network
segment can read it (and change the answer). On the same host, nothing leaves the machine; in
a WireGuard-based VPN every packet is encrypted. For a model on another machine of your
network, put a reverse proxy with a certificate in front of it. A Caddy example (the
certificate is yours; for an internal CA add it to the worker, see below):

```
llm.example.lan {
    tls /etc/caddy/llm.example.lan.pem /etc/caddy/llm.example.lan.key
    reverse_proxy 127.0.0.1:11434
}
```

If the model address is refused with "Plain http only works for a model on the same host as
GarnetOps or inside a VPN", use `https://` as above. GarnetOps shows this when you press
**Test connection** or when a triage runs.

To run the model as a service of the GarnetOps Compose stack, add it with an override file
(`docker-compose.override.yml` next to `docker-compose.yml`) on the worker's `egress`
network, which also lets it download models:

```yaml
services:
  ollama:
    image: ollama/ollama:latest   # pin a version or digest in production
    restart: unless-stopped
    volumes:
      - ollama:/root/.ollama
    networks: [egress]
    # GPU: add the device reservation your Docker setup needs (see the Ollama documentation).
volumes:
  ollama:
```

The address is then `http://ollama:11434/v1`. The worker (not the API) must be on the same
network: it makes every call, and it checks on every connection that the address lies in one
of its own networks.

- **Outside your network** (any public address): only `https://`, and only after you
  confirmed in the settings that finding data may be sent to that host. The settings and the
  panel in every finding show the warning "Findings leave your network" for as long as this
  is so. Changing the host asks again.
- **Never**: `localhost`, loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10,
  which includes cloud metadata), unspecified, multicast and reserved addresses, and
  addresses with a user name in them. Loopback is refused because inside a GarnetOps
  container it is the container itself. If the model runs on the Docker host, use the host's
  gateway address of the worker's Compose network (`docker network inspect garnetops_egress` shows it,
  for example `http://172.18.0.1:11434/v1`), not `localhost`; it lies in the worker's own subnet, so it
  counts as the same host. The model server has to listen on that address.

The settings page checks the address as soon as you save it. In the Compose stack only the
worker has a route to the outside, so the API may not be able to resolve your model's host name;
the address is then saved as "not checked yet", and the worker decides when it connects (the
**Test connection** button shows the result, including "outside your network, please confirm").
The same goes for plain http to an address the API cannot place: only the worker knows its
own networks, so it makes the decision.

The worker connects to the address it resolved and checked, follows no redirects and always
verifies TLS certificates. For a server with a certificate from your own CA, add that CA to
the worker container (`NODE_EXTRA_CA_CERTS`); there is deliberately no "ignore certificate
errors" switch. The worker (not the API) needs a network path to the model, because it makes
every call; in the Compose stack check that its network can reach the model host.

### Limits

| Setting | Default | Range |
| --- | --- | --- |
| Longest answer | 1024 tokens | 64 to 8192 |
| Temperature | 0.2 | 0 to 2 |
| Time limit for one answer | 120 s | 10 to 600 s |
| Answers at the same time (whole organisation) | 2 | 1 to 8 |

Also: 12 requests a minute per person and 40 per organisation, one answer at a time per
conversation, questions up to 2,000 characters. A busy model answers "try again in a moment".

## Using it

Open a finding and press **Ask AI** (from the xwide layout step, 1440p and up, the
conversation is a third pane beside the list and the details and needs no click). **Triage with AI** starts the
structured answer; the text appears as it is written and **Stop** ends it. Below it you can
ask follow-up questions (Enter sends, Shift+Enter starts a new line), **Regenerate** the last
answer, **Copy** it, and **Take over as note** to keep a suggestion on the finding (it is then
listed under Notes in the details, with your name, and in the audit log).

- Everything the model writes is labelled **AI suggestion**. It is advice: it never changes a
  severity, a finding's state, a quality gate result or a setting. You do.
- The conversation belongs to the finding and is shared by your organisation; each question
  shows who asked. Members can ask; viewers can read.
- Answers are shown as text and simple Markdown. HTML in an answer is shown as text, and
  only `http(s)` links work; each link shows its host.
- If the model is off, unreachable or too slow the panel says so; owners and admins get a
  link to **Settings → AI**, everyone else a notice to ask them.

## Fix proposals

The **Fix proposals** page ([docs/fix-prs.md](fix-prs.md)) shows the summary and recommendation of a
finished triage next to the proposal, as labelled read-only text. The model never decides the
version of a proposal or a pull request: it comes from the fixed versions in the vulnerability
data. If the model named another version, the page says so and shows which one GarnetOps proposes.

## Turning it off

Untick **Switch AI triage on** (nothing is sent while it is off, the configuration stays) or
press **Remove configuration** (the key is deleted too). Existing conversations stay readable.

## Security notes

- The API key is stored encrypted and never shown again; only the worker can read it, so
  only the worker talks to the model. It is not in logs, errors or the audit log.
- Every request is in the audit log (**AI** filter) with the finding and the model, never the
  question or the answer. Settings changes, the confirmation for an outside address, tests,
  stopped answers and notes are logged too.
- A model can be wrong, and text in a repository or an advisory can try to steer it. That is
  why it only advises, why the exact input is visible, and why unknown is a valid answer.
