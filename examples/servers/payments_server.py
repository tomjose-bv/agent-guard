"""Sample upstream MCP server: a FAKE payments API (no real money, no network).

Tools: lookup_customer(email), refund(amount, customer_id), ping().

All data is synthetic and generated in-process. Results deliberately contain
PII-looking values (emails, phone numbers, test card numbers) so that
agent-guard's redaction can be demonstrated.

Run directly (stdio):  python examples/servers/payments_server.py
"""

from __future__ import annotations

import itertools

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

server = MCPServer("payments")

# Synthetic customers. 4111 1111 1111 1111 is a well-known public test card number.
CUSTOMERS = {
    "ada@example.com": {
        "customer_id": "cus_ada001",
        "name": "Ada Example",
        "email": "ada@example.com",
        "phone": "+1 415 555 0134",
        "card_on_file": "4111 1111 1111 1111",
    },
    "grace@example.org": {
        "customer_id": "cus_grace02",
        "name": "Grace Sample",
        "email": "grace@example.org",
        "phone": "+44 20 7946 0958",
        "card_on_file": "5555 5555 5555 4444",
    },
}

_refund_ids = itertools.count(1)


@server.tool()
def lookup_customer(email: str) -> dict[str, str]:
    """Look up a customer record by email address."""
    try:
        return CUSTOMERS[email.lower()]
    except KeyError:
        raise ToolError(f"no customer with email {email}") from None


@server.tool()
def refund(amount: float, customer_id: str) -> dict[str, object]:
    """Issue a (fake) refund of `amount` USD to a customer."""
    if amount <= 0:
        raise ToolError("amount must be positive")
    return {"refund_id": f"rf_{next(_refund_ids):05d}", "amount": amount, "customer_id": customer_id, "status": "succeeded"}


@server.tool()
def ping(message: str = "ping") -> str:
    """Echo a message back. Cheap no-op used by the latency benchmark."""
    return message


if __name__ == "__main__":
    server.run()
