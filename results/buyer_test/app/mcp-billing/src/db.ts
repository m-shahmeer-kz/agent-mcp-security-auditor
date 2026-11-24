import pg from "pg";
export const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

export async function findInvoice(invoiceId: string) {
  const r = await pool.query("SELECT id, customer_id, amount_cents, status, pdf_path FROM invoices WHERE id = $1", [invoiceId]);
  return r.rows[0];
}

export async function searchCustomers(term: string) {
  const r = await pool.query("SELECT id, name, email FROM customers WHERE name ILIKE $1 LIMIT 20", [`%${term}%`]);
  return r.rows;
}
