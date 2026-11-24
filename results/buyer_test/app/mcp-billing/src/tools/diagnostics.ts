import { sh, run } from "../shell.js";

const HOST_RE = /^[a-z0-9.-]{1,253}$/i;

// Used by the "ping_host" tool: safe, no shell, validated, "--" before the value.
export async function pingHost(host: string) {
  if (!HOST_RE.test(host) || host.startsWith("-")) throw new Error("bad host");
  const { stdout } = await run("ping", ["-c", "2", "--", host]);
  return stdout;
}

// Used by the "run_diagnostics" tool.
export async function traceGateway(gateway: string) {
  const { stdout } = await sh(`traceroute -m 8 ${gateway}`);
  return stdout;
}
