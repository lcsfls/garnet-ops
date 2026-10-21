import { spawn } from "node:child_process";

export class CommandError extends Error {
  readonly exitCode: number | null;
  readonly stderr: string;

  constructor(message: string, exitCode: number | null, stderr: string) {
    super(message);
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

/**
 * Runs a binary without a shell, with a timeout and bounded output capture.
 * Arguments are passed as an array, so nothing is ever interpreted by a shell.
 * `redact` strings are removed from captured stderr before it is returned.
 */
export function run(
  command: string,
  args: string[],
  options: { cwd?: string; env: NodeJS.ProcessEnv; timeoutMs: number; redact?: string[] },
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const limit = 64 * 1024;
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => {
      if (stdout.length < limit) stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < limit) stderr += d.toString("utf8");
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), options.timeoutMs);
    const scrub = (s: string) =>
      (options.redact ?? []).filter(Boolean).reduce((acc, secret) => acc.split(secret).join("[redacted]"), s);
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(new CommandError(`Could not start ${command}: ${error.message}`, null, ""));
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (signal === "SIGKILL") return reject(new CommandError(`${command} timed out`, null, scrub(stderr)));
      if (code !== 0)
        return reject(new CommandError(`${command} exited with code ${code}`, code, scrub(stderr)));
      resolve({ stdout, stderr: scrub(stderr) });
    });
  });
}
