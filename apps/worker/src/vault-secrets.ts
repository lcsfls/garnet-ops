/**
 * Sealed secrets the worker itself opens and stores (ADR 0004): it holds the vault's private key, so it can also seal,
 * for the tokens it receives from a forge when someone signs in (ADR 0031).
 */
import { newId } from "@garnetops/core";
import { open, type SecretPurpose, seal, vaultPublicKeyOf } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { and, eq } from "drizzle-orm";
import { db } from "./db.ts";
import { vaultPrivateKey } from "./env.ts";

const publicKey = vaultPublicKeyOf(vaultPrivateKey);

type Executor = Pick<typeof db, "insert">;

/** The text of a sealed secret of this organisation and purpose, or null when it is missing or sealed for another. */
export async function openSecretText(
  id: string | null,
  organizationId: string,
  purpose: SecretPurpose,
): Promise<string | null> {
  if (!id) return null;
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, id),
        eq(schema.secret.organizationId, organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!secret) return null;
  try {
    const plain = open(secret.sealed, { organizationId, recordId: secret.id, purpose }, vaultPrivateKey);
    const text = plain.toString("utf8");
    plain.fill(0);
    return text;
  } catch {
    return null;
  }
}

/** Seals `plain` as a new secret and returns its id. */
export async function sealSecret(
  executor: Executor,
  organizationId: string,
  purpose: SecretPurpose,
  plain: string,
): Promise<string> {
  const id = newId("sec");
  await executor.insert(schema.secret).values({
    id,
    organizationId,
    purpose,
    sealed: seal(plain, { organizationId, recordId: id, purpose }, publicKey),
    vaultKeyId: publicKey.id,
  });
  return id;
}
