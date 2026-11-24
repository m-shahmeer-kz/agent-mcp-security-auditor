import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { findInvoice, searchCustomers } from "./db.js";
import { pingHost, traceGateway } from "./tools/diagnostics.js";
import { readKbArticle, exportReport } from "./tools/reports.js";
import { refund } from "./payments.js";

const server = new McpServer({ name: "acme-billing", version: "0.3.0" });

server.tool("search_customers", "Search customers by name. Call this first to get a customer id for other tools.",
  { term: z.string() }, async ({ term }) => ({ content: [{ type: "text", text: JSON.stringify(await searchCustomers(term)) }] }));

server.tool("get_invoice", "Get an invoice by id, including the customer's billing details.",
  { invoice_id: z.string() }, async ({ invoice_id }) => {
    const inv = await findInvoice(invoice_id);
    return { content: [{ type: "text", text: JSON.stringify(inv) }] };
  });

server.tool("refund_payment", "Refund a payment in full.",
  { payment_id: z.string(), reason: z.string() }, async ({ payment_id, reason }) => {
    const r = await refund(payment_id, reason);
    return { content: [{ type: "text", text: `refunded ${r.amount}` }] };
  });

server.tool("read_kb_article", "Read a help-center article by slug.",
  { slug: z.string() }, async ({ slug }) => ({ content: [{ type: "text", text: await readKbArticle(slug) }] }));

server.tool("export_report", "Save rows as a JSON report file.",
  { output_path: z.string(), rows: z.array(z.any()) }, async ({ output_path, rows }) => ({ content: [{ type: "text", text: await exportReport(output_path, rows) }] }));

server.tool("ping_host", "Check that a payment gateway host answers.",
  { host: z.string() }, async ({ host }) => ({ content: [{ type: "text", text: await pingHost(host) }] }));

server.tool("run_diagnostics", "Trace the network path to a payment gateway.",
  { gateway: z.string() }, async ({ gateway }) => ({ content: [{ type: "text", text: await traceGateway(gateway) }] }));

const app = express();
app.use(express.json());
app.post("/mcp", async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});
app.listen(8080, "0.0.0.0", () => console.log("billing MCP on :8080"));
