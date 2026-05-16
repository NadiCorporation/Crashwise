<!--
  SPDX-License-Identifier: MIT
  Copyright (c) 2026 CrashWise Contributors
-->

# Contributing

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/Crashwise.git && cd Crashwise
uv sync
cp .env.example .env   # configure LLM keys
uv run pytest tests/unit/ -v
```

Optional (integration tests):
```bash
docker compose up -d temporal-server postgres redis
uv run pytest tests/integration/ -v -m integration
```

---

## Workflow

1. Branch from `main`: `git checkout -b feature/description`
2. Implement changes per the standards below
3. Run checks:
   ```bash
   uv run ruff check crashwise/ tests/
   uv run ruff format --check crashwise/ tests/
   uv run mypy crashwise/
   uv run pytest tests/
   ```
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
5. Open PR against `main`

---

## Coding Standards

### File headers

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
```

### Type annotations

- All functions and class attributes must be typed
- `from __future__ import annotations` for forward references
- `mypy --strict` must pass with zero errors
- Avoid `Any` unless unavoidable

### Pydantic models

- Cross-component payloads (Temporal, API) use models from `crashwise.core.models`
- Extend `_StrictModel` (extra="forbid", validate_assignment=True)
- All public fields require `Field(..., description="...")`

### Temporal workflows

- Workflows are **deterministic** — no `random`, `time.time()`, or I/O
- All non-determinism lives in activities
- Activities referenced by string name in `execute_activity()`

### Logging

- Use `crashwise.core.logging.get_logger(__name__)`
- Structured: `log.info("event_name", key=value)`
- Never `print()` in production code

### Error handling

- Catch at activity boundaries, return structured responses
- Never swallow exceptions silently

---

## Testing

### Requirements

- All new features require unit tests in `tests/unit/test_<module>.py`
- Target >80% coverage on new code
- Mock external services (Temporal, Docker, LLM APIs)
- Use `pytest-asyncio` for async tests

### Commands

```bash
uv run pytest tests/unit/ -v                          # unit tests
uv run pytest tests/ --cov=crashwise --cov-report=html  # coverage
uv run pytest tests/unit/test_exploit_gen.py -v       # single file
```

### Mocking

- `unittest.mock.patch` or `pytest-mock`
- Temporal: mock `activity.info()` → `MagicMock`
- LLM: mock `get_chat_model()` and `ainvoke`
- Database: `AsyncMock` for `get_session()`

---

## Commit Format

```
<type>(<scope>): <description>
```

| Type | Usage |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `refactor` | No behavior change |
| `test` | Test additions/updates |
| `chore` | Build, deps, tooling |
| `security` | Security fix |

---

## Pull Requests

- Clear title and description
- Link issues: `Closes #123`
- CI must pass (lint, type-check, test, Docker build)
- Squash and merge once approved

### Checklist

- [ ] Tests pass
- [ ] Lint clean
- [ ] Type check clean
- [ ] CHANGELOG.md updated (if user-facing)

---

## Security

Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

---

## License

Contributions are licensed under [MIT](./LICENSE).
