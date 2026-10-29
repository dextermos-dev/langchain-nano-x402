# langchain-nano-x402

Framework-native LangChain tool enabling autonomous AI agents to buy and consume pay-per-call HTTP resources over the **Nano (XNO) x402 protocol** (`nano:mainnet`), secured by strict client-side spend guards and zero-double-sign protections.

Published for **Initiative #13 (Slot 1: LangChain)** under the [pursekeeper integrations bounty](https://pursekeeper.dev/integrations).

---

## Features

- **Framework-Native**: Exposes `NanoX402Tool` deriving directly from LangChain's `BaseTool`.
- **Payment Guard**: Every payment quote must satisfy 7 offline security invariants before any block is signed:
  1. `network == "nano:mainnet"` (foreign networks rejected).
  2. `payTo` allowlist verification (optional operator pin).
  3. Per-call amount cap enforcement.
  4. Cumulative session spend cap enforcement.
  5. Deterministic request deduplication (never signs twice for the same request).
  6. Origin redirect protection (never pays cross-origin redirects).
  7. Quote expiration and structural validation.
- **Zero Secrets Leakage**: Private keys and seeds are injected via environment variables (`NANO_SEED` or `NANO_PRIVATE_KEY`) or passed as custom signers — never hardcoded, printed, or logged.
- **Single-Attempt Semantics**: Signs exactly one send block per call. No automatic retry loop on non-2xx.

---

## Installation

```bash
pip install langchain-nano-x402
```

Or with `uv`:
```bash
uv add langchain-nano-x402
```

---

## Usage in a LangChain Agent Loop

```python
import os
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI
from langchain_nano_x402 import NanoX402Tool, PaymentGuardConfig

# 1. Configure local spend bounds
guard_config = PaymentGuardConfig(
    max_amount_raw_per_call=10**27,      # Cap: 0.001 XNO per call
    cumulative_cap_raw=10**28,           # Cap: 0.01 XNO cumulative session spend
    allowed_network="nano:mainnet",
)

# 2. Instantiate framework-native tool
tool = NanoX402Tool(guard_config=guard_config)
tools = [tool]

# 3. Bind to an agent loop
llm = ChatOpenAI(model="gpt-4o", temperature=0)
prompt = PromptTemplate.from_template(
    "Answer the question using tools: {tools}\n{tool_names}\nQuestion: {input}\n{agent_scratchpad}"
)
agent = create_react_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# 4. Agent autonomously executes paid x402 fetch
result = executor.invoke({
    "input": "Fetch the echo verification message from https://pursekeeper.dev/v1/echo?msg=hello"
})
print("Result:", result["output"])
```

---

## Offline Security Tests

Run the complete offline test suite (100% mocked, 0 network access):

```bash
pytest tests/ -v
```

All 9 test cases assert strict rejection of malformed quotes, network mismatches, allowlist bypasses, per-call and cumulative cap breaches, duplicate invocations, and redirect origin mismatches.

---

## License

MIT © Dexter Mos / BountyHunter AI
