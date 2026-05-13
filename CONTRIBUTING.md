# Contributing to CrashWise

Thank you for your interest in contributing to CrashWise! This document
outlines the standards and processes established by **Yahya Toubali**,
Security Researcher, for the CrashWise project — developed under the
**Nadicorp** label.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Commit Message Format](#commit-message-format)
- [Pull Request Process](#pull-request-process)
- [Security](#security)
- [License](#license)

---

## Code of Conduct

- Be respectful and constructive in all interactions.
- Focus on the technical merits of contributions.
- Harassment, discrimination, or toxic behavior will not be tolerated.

---

## Getting Started

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Docker & Docker Compose v2
- Git

### Setup

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/Crashwise.git
cd Crashwise

# 2. Install dependencies
uv sync

# 3. Configure environment
cp .env.example .env
# Edit .env — see README.md "LLM Configuration" for details

# 4. Start infrastructure (optional — only needed for integration tests)
docker compose up -d temporal-server postgres redis

# 5. Run tests to verify setup
uv run pytest tests/unit/ -v

# 6. Configure pre-commit hooks (optional but recommended)
uv run pre-commit install
```

---

## Development Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below.

3. **Run quality checks** before committing:
   ```bash
   uv run ruff check crashwise/ tests/
   uv run ruff format --check crashwise/ tests/
   uv run mypy crashwise/ --config-file pyproject.toml
   uv run pytest tests/
   ```

4. **Commit** with a descriptive message (see [Commit Message Format](#commit-message-format)).

5. **Push** and open a Pull Request against `main`.

---

## Coding Standards

### File Headers

Every source file MUST include the SPDX license identifier:

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 CrashWise Contributors
```

### Type Annotations

- All functions, methods, and class attributes must be typed.
- Use `from __future__ import annotations` for forward references.
- `mypy --strict` must pass with zero errors.
- Avoid `Any` unless absolutely necessary (e.g., kwargs, loggers).

### Pydantic Models

- Every cross-component boundary (Temporal workflows, activities, APIs) must use
  Pydantic models.
- Models should extend `_StrictModel` from `crashwise.core.models`.
- Add `Field(..., description="...")` for all public attributes.

### Temporal Workflows

- Workflows must be **deterministic**. No `random`, `time.time()`, or I/O in
  workflow modules.
- All non-determinism lives in **activities**.
- Activities are referenced by string name in `execute_activity()` calls.

### Logging

- Use `structlog` via `crashwise.core.logging.get_logger(__name__)`.
- Prefer structured logging: `log.info("event_name", key=value)`.
- Never use `print()` in production code.

### Error Handling

- Catch exceptions at activity boundaries and return structured error responses.
- Use `Tenacity` for retry logic on external calls.
- Never swallow exceptions silently — log them.

---

## Testing Requirements

### Test Coverage

- All new features must include unit tests.
- Tests should be in `tests/unit/` and named `test_<module>.py`.
- Aim for >80% coverage on new code.
- Use `pytest-asyncio` for async tests.
- Mock external services (Temporal, Docker, LLM APIs) — never hit real
  infrastructure in unit tests.

### Running Tests

```bash
# Full suite (unit tests — no infrastructure required)
uv run pytest tests/unit/ -v

# With coverage
uv run pytest tests/ --cov=crashwise --cov-report=html

# Specific test file
uv run pytest tests/unit/test_exploit_gen.py -v

# Integration tests (require docker-compose stack running)
docker compose up -d temporal-server postgres redis
uv run pytest tests/integration/ -v -m integration
```

### Mocking Guidelines

- Use `unittest.mock.patch` or `pytest-mock` for mocking.
- For Temporal activities, mock `activity.info()` to return a MagicMock.
- For LLM calls, mock `get_chat_model()` and its `ainvoke` method.
- For database operations, use `AsyncMock` for `get_session()`.

---

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | Use When |
|------|----------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Code style (formatting, no logic change) |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Adding or updating tests |
| `chore` | Build process, dependencies, tooling |
| `ci` | CI/CD configuration |
| `security` | Security fix |

### Examples

```
feat(triage): add exploit architect agent for PoC generation

Implements a LangGraph node that transforms CrashReport into
standalone C exploit scripts with reachability analysis.

Refs: #15
```

```
fix(verification): handle git apply failures gracefully

Falls back to `patch` CLI when `git apply` rejects the patch
due to context mismatch.
```

```
test(exploit): add 35 unit tests for PoC generation pipeline

Covers primitive detection, LLM generation, template fallback,
reachability engine, compilation, and execution.
```

---

## Pull Request Process

1. **Open a PR** against `main` with a clear title and description.
2. **Link issues** using `Closes #123` or `Refs #123`.
3. **Ensure CI passes**: The PR must pass all GitHub Actions checks
   (lint, type-check, test, Docker build).
4. **Request review** from at least one maintainer.
5. **Address feedback** promptly and push updates.
6. **Squash and merge** once approved. The merge commit should follow the
   conventional commit format.

### PR Description Template

```markdown
## Summary
Brief description of the change.

## Changes
- Change 1
- Change 2

## Testing
- How was this tested?
- Test coverage impact?

## Checklist
- [ ] Tests pass (`uv run pytest`)
- [ ] Lint passes (`uv run ruff check`)
- [ ] Type check passes (`uv run mypy`)
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated (if applicable)
```

---

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability in CrashWise, please **do not** open a
public issue. Instead, email crashwise@yahyatoubali.me with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and coordinate a responsible disclosure timeline.

### Secure Coding Practices

- Never commit secrets (API keys, passwords) to the repository.
- Use `pydantic.SecretStr` for sensitive configuration fields.
- Validate all inputs with Pydantic models.
- Use parameterized queries (SQLAlchemy ORM) — never raw SQL concatenation.
- Sanitize file paths before filesystem operations.
- Run fuzz targets with minimal privileges (Docker `--cap-drop ALL`).

---

## License

By contributing to CrashWise, you agree that your contributions will be licensed
under the [MIT License](./LICENSE).

---

## Questions?

- Open a [Discussion](https://github.com/yahyatoubali/Crashwise/discussions) for general questions.
- Open an [Issue](https://github.com/yahyatoubali/Crashwise/issues) for bugs or feature requests.
- Email crashwise@yahyatoubali.me for private inquiries.

**Thank you for helping make CrashWise better!**
