import { exec, execFile } from "child_process";
import { promisify } from "util";
export const sh = promisify(exec);
export const run = promisify(execFile);
