const STRIPE = process.env.STRIPE_SECRET_KEY!;
export async function refund(paymentId: string, reason: string) {
  const r = await fetch("https://api.stripe.com/v1/refunds", {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE}`, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ payment_intent: paymentId, reason: "requested_by_customer", "metadata[note]": reason }),
  });
  return r.json();
}
