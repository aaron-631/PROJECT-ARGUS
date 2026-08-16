# Indirect injection proof

This isolated demo models a practical RAG failure path:

```text
poisoned SQLite record -> agent context -> dangerous tool proposal -> Argus policy -> BLOCK
```

Run it from the repository root:

```bash
.venv/bin/python examples/indirect-injection/run_demo.py
```

It prints a reproducible JSON proof with `decision: BLOCK`, `side_effects: 0`,
and `canary_modified: false`. The fake agent and database are intentional: the
demo proves the tool boundary without executing a shell command or contacting
an external system. The live dynamic module uses the same metadata contract to
send retrieved context to an authorized model endpoint.
