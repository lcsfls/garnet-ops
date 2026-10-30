/**
 * The public DNS resolvers an organisation may add for lookups of public names (website checks, the proof of control, registry
 * checks, Certificate Transparency). Off by default: the names looked up are sent to the provider, which is data leaving the
 * network. The local resolver keeps answering everything else (forges, directory, mail, AI endpoint).
 */
export const PUBLIC_DNS_PROVIDERS = {
  cloudflare: {
    name: "Cloudflare (1.1.1.1)",
    servers: ["1.1.1.1", "1.0.0.1"],
    privacy: "https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/",
  },
  google: {
    name: "Google Public DNS (8.8.8.8)",
    servers: ["8.8.8.8", "8.8.4.4"],
    privacy: "https://developers.google.com/speed/public-dns/privacy",
  },
  quad9: {
    name: "Quad9 (9.9.9.9)",
    servers: ["9.9.9.9", "149.112.112.112"],
    privacy: "https://quad9.net/privacy/policy/",
  },
} as const;

export type PublicDnsProvider = keyof typeof PUBLIC_DNS_PROVIDERS;
export const PUBLIC_DNS_IDS = Object.keys(PUBLIC_DNS_PROVIDERS) as [
  PublicDnsProvider,
  ...PublicDnsProvider[],
];

export const isPublicDnsProvider = (value: unknown): value is PublicDnsProvider =>
  typeof value === "string" && Object.hasOwn(PUBLIC_DNS_PROVIDERS, value);
