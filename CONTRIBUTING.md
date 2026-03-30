# Contributing to VICE

Thanks for your interest in contributing to VICE!

## How to contribute

1. **Fork** the repository
2. **Create a branch** for your feature: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -m "Add my feature"`
4. **Push** to your branch: `git push origin feature/my-feature`
5. Open a **Pull Request**

## Adding a new module

### Remote module (black-box scan)
Add your module in `src/remote/` and register it in `scan.js`.

### Local module (white-box audit)
1. Create your module in `src/local/your-module.js`
2. Export an async function: `export async function auditYourModule(projectPath, spinner)`
3. Use `addFinding()` from `src/core/findings.js` to report issues
4. Register it in `src/local/index.js`

## Finding format

```js
addFinding(
  'CRITIQUE',           // CRITIQUE | ELEVEE | MOYENNE | FAIBLE | INFO
  'Module Name',        // Module name shown in report
  'Short title',        // One-line summary
  'Detailed info',      // Full detail with file paths, values, etc.
  'How to fix this'     // Concrete fix with code examples
);
```

## Guidelines

- Always provide a concrete fix recommendation
- Test on real projects before submitting
- Keep false positives low — precision over recall
- French severity levels: CRITIQUE, ELEVEE, MOYENNE, FAIBLE, INFO

## Code style

- ES Modules (import/export)
- Async/await
- No TypeScript (keep it simple)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
