/**
 * Password hashing with Argon2id (AGENTS.md rule 1), using `node:crypto` only.
 *
 * Hashes are stored as PHC strings, so the parameters travel with every hash:
 *   $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>   (salt and hash: base64 without padding)
 * Parameters follow the second recommended option of RFC 9106 (64 MiB, 3 passes,
 * 4 lanes). Raising them later only affects new hashes; old ones keep verifying
 * with the parameters stored in them.
 *
 * Argon2id is not weakened in any practical way by quantum computers (only
 * Grover's square-root speed-up applies), so it needs no post-quantum variant.
 */
import { argon2, randomBytes, timingSafeEqual } from "node:crypto";

export const ARGON2_PARAMS = { memory: 65_536, passes: 3, parallelism: 4, tagLength: 32 } as const;
const SALT_BYTES = 16;
/** Upper bounds when reading stored hashes, so a tampered row cannot make us burn memory or CPU. */
const MAX = { memory: 1_048_576, passes: 10, parallelism: 16 };

function derive(
  password: string,
  salt: Buffer,
  params: { memory: number; passes: number; parallelism: number; tagLength: number },
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    argon2("argon2id", { message: password, nonce: salt, ...params }, (error, key) =>
      error ? reject(error) : resolve(key),
    );
  });
}

const b64 = (buf: Buffer) => buf.toString("base64").replace(/=+$/, "");

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await derive(password, salt, ARGON2_PARAMS);
  const { memory: m, passes: t, parallelism: p } = ARGON2_PARAMS;
  return `$argon2id$v=19$m=${m},t=${t},p=${p}$${b64(salt)}$${b64(hash)}`;
}

const PHC =
  /^\$argon2id\$v=19\$m=(\d{1,7}),t=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]{22,})\$([A-Za-z0-9+/]{43,})$/;

/** Returns false for a wrong password and for anything that is not one of our Argon2id hashes. */
export async function verifyPassword(stored: string, password: string): Promise<boolean> {
  const match = PHC.exec(stored);
  if (!match) return false;
  const [, m, t, p, saltB64, hashB64] = match as unknown as [string, string, string, string, string, string];
  const params = { memory: Number(m), passes: Number(t), parallelism: Number(p) };
  if (params.memory > MAX.memory || params.passes > MAX.passes || params.parallelism > MAX.parallelism)
    return false;
  if (params.passes < 1 || params.parallelism < 1 || params.memory < 8 * params.parallelism) return false;
  const expected = Buffer.from(hashB64, "base64");
  const actual = await derive(password, Buffer.from(saltB64, "base64"), {
    ...params,
    tagLength: expected.length,
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
