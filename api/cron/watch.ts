import type { IncomingMessage, ServerResponse } from "node:http";
import { HOST } from "../../src/config.js";
import { executeCron } from "../../src/watch-job.js";

export const maxDuration = 30;

function header(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  return Array.isArray(value) ? value[0] : value;
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const base = process.env.APP_BASE_URL?.trim().replace(/\/$/, "") || HOST;
  const result = await executeCron(header(req, "authorization"), header(req, "x-cron-secret"), base);
  res.statusCode = result.status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(result.body));
}
