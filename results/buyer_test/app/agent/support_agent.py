"""Customer-support agent: answers tickets, can browse the web and use the billing MCP server."""
import requests
from langchain_community.tools import ShellTool
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page the customer linked in their ticket and return its text."""
    return requests.get(url, timeout=10).text[:20000]


@tool
def lookup_status(service: str) -> str:
    """Look up the public status of one of our services."""
    allowed = {"api": "https://status.acme.example/api.json", "web": "https://status.acme.example/web.json"}
    if service not in allowed:
        return "unknown service"
    return requests.get(allowed[service], timeout=5).text


def build_agent():
    llm = ChatOpenAI(model="gpt-4.1")
    tools = [fetch_page, lookup_status, ShellTool()]
    return create_react_agent(llm, tools, prompt="You are Acme's support agent. Resolve the customer's ticket.")


if __name__ == "__main__":
    agent = build_agent()
    ticket = open("ticket.txt").read()
    print(agent.invoke({"messages": [("user", ticket)]}))
