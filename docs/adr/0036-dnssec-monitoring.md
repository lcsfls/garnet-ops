# ADR 0036: DNSSEC monitoring in website checks

- Status: accepted (2026-10-30)
- Date: 2026-10-30
- Decided by: maintainer (check DNSSEC of each website's zone in stage 1, with the chain checked by GarnetOps itself)
- Builds on: ADR 0023 and 0033 (website monitoring), the amendment of ADR 0033 (asking the zone's own name servers), AGENTS.md rules 1
  and 3

## Context

A DNSSEC mistake takes a whole domain offline for every user behind a validating resolver, and it happens quietly: a key rollover
where the DS record at the registrar was not updated, a signer that stopped re-signing, an expired signature. Until now the checks
said "DNSSEC: not checked", because the resolver interface of Node.js neither asks for DNSSEC records nor says whether an answer was
validated.

## Decision

1. **Ask the source.** For a domain asset the worker finds its zone (the NS answer of the name or its nearest parent) and the parent
   zone, resolves their name servers under the address policy (public addresses only) and sends one query each, with EDNS and the DO
   bit, over UDP and over TCP when the answer is truncated: DS at the parent's servers, DNSKEY and SOA at the zone's. Answers are
   parsed with dns-packet (MIT), matched against the question and the query id, and cut to 50 records.
2. **Check the chain here**, with node:crypto: a DS record must match a key (key tag, algorithm, SHA-1/SHA-256/SHA-384 digest over the
   owner name and the key); a key named by a DS record must have signed the DNSKEY set; a key of the zone must have signed the SOA
   record; each signature must be within its validity period. Supported: RSA/SHA-1, RSA/SHA-256, RSA/SHA-512, ECDSA P-256 and P-384,
   Ed25519, Ed448. A signature with another algorithm is shown and not counted either way.
3. **States and findings.** `unsigned` (low: DNSSEC not set up), `insecure` (medium: signed, but no DS at the parent), `broken` (high,
   with the failing step), `secure`. A secure zone whose signatures run out within 24 hours (medium; live signers keep days ahead),
   an outdated algorithm per RFC 8624 (medium) and DS records with SHA-1 only (low) are findings of their own.
4. **"Could not ask" is not "fixed".** When no name server answers, the snapshot says `unknown` and the DNSSEC findings stay as they
   were, as for every other lookup that fails.

The tests check the implementation against signed zones made by dnspython, an independent implementation, for every supported family
of algorithms, plus tampered signatures, changed records, expired signatures and DS records that name no key.

## Threat model

| Threat | Control |
| --- | --- |
| A name server answers with hostile or huge data | dns-packet parses, only records for the question asked are used, at most 50 per type; only numbers and dates are stored |
| A spoofed UDP answer | the random query id and the question must match; a forged answer can at worst make a zone look broken until the next run, never make GarnetOps connect anywhere |
| DNS queries to internal servers | name server addresses go through the address policy; a name server that resolves to a non-public address is not asked |
| Signature checks with weak or unknown algorithms | unknown algorithms are not counted; weak ones are reported |

## Consequences

- New dependency dns-packet (MIT) with @leichtgewicht/ip-codec (MIT) in the worker (`docs/COMPONENTS.md`).
- Outgoing DNS (UDP and TCP port 53) to the zone's and the parent's name servers; where it is blocked DNSSEC shows "not checked".
- Not in this version: denial of existence (NSEC, NSEC3), checking every name of a zone, CDS/CDNSKEY automation.
