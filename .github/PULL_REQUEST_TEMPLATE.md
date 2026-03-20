## Summary

<!-- Briefly describe what this PR does and why. -->

## Related Issues

<!-- Link related issues: Closes #123, Fixes #456 -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing behaviour to change)
- [ ] Documentation update
- [ ] Refactor (no functional change)
- [ ] CI/CD change

## Testing

Describe how you tested the changes. Include relevant command output.

```
pytest tests/unit/ -v
```

## Checklist

- [ ] Tests added or updated for the changed code
- [ ] `ruff check src/ tests/` passes with no errors
- [ ] `ruff format --check src/ tests/` passes
- [ ] `mypy src/` passes with no errors
- [ ] README.md updated if the change affects user-facing behaviour or configuration
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] No secrets, credentials, or personally identifiable information included
