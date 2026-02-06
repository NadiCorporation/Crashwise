# Phase 1 & 2 Validation Checklist

## Phase 1A: LLM Resolver & Policy System

### New Files Created
1. ✅ `cli/src/crashwise_cli/policy.py` - Policy enforcement
2. ✅ `cli/src/crashwise_cli/llm_resolver.py` - Single source of truth for LLM config
3. ✅ `cli/tests/test_policy.py` - Policy tests
4. ✅ `cli/tests/test_llm_resolver.py` - Resolver tests

### Validation Commands

```bash
# Test policy module
python -m pytest cli/tests/test_policy.py -v

# Test LLM resolver
python -m pytest cli/tests/test_llm_resolver.py -v

# Verify imports work
python -c "from crashwise_cli.policy import Policy; print('Policy OK')"
python -c "from crashwise_cli.llm_resolver import get_llm_client; print('Resolver OK')"
```

### Policy Features Verified
- [ ] Default deny-by-default behavior
- [ ] Provider allow/block lists work
- [ ] Env var fallback can be disabled
- [ ] Limits can be configured
- [ ] Policy file loads from ~/.config/crashwise/policy.yaml

### LLM Resolver Features Verified
- [ ] OAuth tokens preferred over env vars
- [ ] get_llm_client() returns complete config
- [ ] get_litellm_config() returns LiteLLM-compatible format
- [ ] Policy violations raise PolicyViolationError
- [ ] No credentials raises LLMResolverError
- [ ] API keys never logged

---

## Phase 2: OAuth UX Polish

### Enhanced Commands

#### `ff oauth status --json`
```bash
# Test JSON output (safe for scripting)
ff oauth status --json

# Verify output contains NO tokens
ff oauth status --json | grep -i token  # Should be empty

# Verify output is valid JSON
ff oauth status --json | python -m json.tool > /dev/null && echo "Valid JSON"
```

#### `ff oauth logout`
```bash
# Setup a provider first
ff oauth setup -p openai_codex  # Complete OAuth flow

# Test logout
ff oauth logout -p openai_codex

# Verify logged out
ff oauth status  # Should show "Not configured"

# Test logout --force (no confirmation)
ff oauth setup -p openai_codex  # Setup again
ff oauth logout -p openai_codex --force  # No prompt
```

#### `ff oauth setup --list-providers`
```bash
# List providers
ff oauth setup --list-providers

# Verify table format
ff oauth setup -l

# Should show provider IDs and names
```

### Security Verification

```bash
# Verify tokens never displayedf oauth status 2>&1 | grep -E "[a-zA-Z0-9_-]{20,}" || echo "No tokens in output"

# Verify --json output safe
ff oauth status --json 2>&1 | grep -i "token" || echo "Safe for scripting"
```

---

## Integration Tests

### End-to-End Flow

```bash
# 1. Start with no credentials
ff oauth status  # Should show "Not configured"

# 2. List available providers
ff oauth setup --list-providers

# 3. Setup OAuth (manual - requires browser)
ff oauth setup -p openai_codex

# 4. Check status
ff oauth status
ff oauth status --json

# 5. Verify resolver can use credentials
python -c "
from crashwise_cli.llm_resolver import get_llm_client
config = get_llm_client(provider='openai_codex')
print(f'Provider: {config[\"provider\"]}')
print(f'Model: {config[\"model\"]}')
print(f'Auth: {config[\"auth_method\"]}')
print('Token available:', bool(config['api_key']))
"

# 6. Logout
ff oauth logout -p openai_codex --force

# 7. Verify resolver fails gracefully
python -c "
from crashwise_cli.llm_resolver import get_llm_client, LLMResolverError
try:
    config = get_llm_client(provider='openai_codex')
    print('ERROR: Should have failed')
except LLMResolverError as e:
    print('Good: Resolver correctly failed')
    print(f'Error: {e}')
"
```

### Policy Enforcement

```bash
# Create restrictive policy
cat > ~/.config/crashwise/policy.yaml << 'EOF'
providers:
  allowed:
    - openai_codex
  blocked:
    - openai

fallback:
  allow_env_vars: false

limits:
  requests_per_minute: 10
EOF

# Test policy enforcement
python -c "
from crashwise_cli.llm_resolver import get_llm_client, PolicyViolationError

# Should work - openai_codex is allowed
try:
    config = get_llm_client(provider='openai_codex')
    print('openai_codex: OK')
except Exception as e:
    print(f'openai_codex: {e}')

# Should fail - openai is blocked via env
try:
    config = get_llm_client(provider='openai')
    print('ERROR: openai should be blocked')
except PolicyViolationError as e:
    print(f'openai correctly blocked: {e}')
"
```

---

## Regression Tests

### Existing Functionality

```bash
# Test existing CLI commands still work
ff --help
ff init --help
ff workflow --help
ff config --help

# Test OAuth setup still works
ff oauth setup --help
ff oauth status --help
ff oauth remove --help
```

### Backward Compatibility

```bash
# Verify exception imports work
python -c "
from crashwise_cli.exceptions import (
    CrashwiseError,
    ValidationError,
    ProjectNotFoundError
)
print('Exception imports: OK')
"

# Verify SDK exceptions still work
python -c "
from crashwise_sdk.exceptions import CrashwiseError
print('SDK exceptions: OK')
"
```

---

## Expected Test Results

### All tests should pass:

```bash
# Run all new tests
python -m pytest cli/tests/test_policy.py cli/tests/test_llm_resolver.py -v

# Expected output:
# ================== test session starts ==================
# cli/tests/test_policy.py::TestProviderPolicy::test_empty_policy_allows_all PASSED
# cli/tests/test_policy.py::TestProviderPolicy::test_allowed_list_restricts PASSED
# ... (all tests pass)
# ================== X passed in Y.YYs ==================
```

### Manual verification:

```bash
# Verify no tokens in any output
ff oauth status 2>&1 | tee /tmp/oauth_status.txt
cat /tmp/oauth_status.txt | wc -c  # Should be reasonable size

ff oauth status --json 2>&1 | tee /tmp/oauth_status.json
cat /tmp/oauth_status.json | python -m json.tool > /dev/null && echo "Valid JSON"
```

---

## Files Changed Summary

### New Files:
1. `cli/src/crashwise_cli/policy.py` (220 lines)
2. `cli/src/crashwise_cli/llm_resolver.py` (310 lines)
3. `cli/tests/test_policy.py` (260 lines)
4. `cli/tests/test_llm_resolver.py` (340 lines)

### Modified Files:
1. `cli/src/crashwise_cli/commands/oauth.py` (enhanced)
   - Added `--json` flag to status
   - Added `logout` command
   - Added `--list-providers` flag to setup
   - Added `--force` flag to remove/logout

### Total:
- ~1,130 lines of new code
- ~150 lines modified
- 100% backward compatible
- Zero breaking changes
