# Contributing

Contributions are welcome, but this project has a strict clean-repository boundary.

## Never submit proprietary material

Do not commit, paste, attach or upload:

- XCI, NSP, NCA, NSO, NRO, RomFS or ExeFS content;
- console keys, tickets, certificates or firmware;
- game assets, saves or copyrighted binaries;
- generated code, shaders, patches or metadata derived directly from private game files;
- hashes, file listings or paths that identify a contributor's private dump;
- CI artifacts containing any of the above.

If a report depends on private inputs, describe the observable behaviour using sanitized counts, booleans and synthetic reproduction cases. Maintainers may close and remove submissions that cross this boundary.

## Before opening a pull request

1. Open or comment on an issue for substantial changes.
2. Keep the change narrowly scoped and fail closed at parsing, mapping and execution boundaries.
3. Add non-proprietary tests for every new contract or bug fix.
4. Run:

```bash
python -m unittest discover -s tests -v
```

5. Run the relevant `tools/test_*.sh` host suites.
6. Run `git diff --check`.
7. Confirm `git status --ignored` does not reveal accidentally staged private or build material.

## Engineering rules

- Bounds and integer-overflow checks precede allocation, mapping or writes.
- Validation completes before mutation where practical.
- Rollback paths must be tested independently.
- Unknown ABI, service, fault or GPU behaviour stops the experiment; do not continue optimistically.
- Synthetic tests must not be described as game execution or rendering.
- Physical-device claims must identify the tested capability without publishing personal identifiers.
- Avoid importing emulator-scale code without a documented role and compatible licence.

## Commit and pull-request content

Use concise, imperative commit subjects. Pull requests should state:

- the exact boundary changed;
- what is observed versus inferred;
- tests run and their results;
- remaining unknowns;
- whether private inputs were used locally and how all published evidence was sanitized.

By contributing, you agree that your contribution is licensed under the repository's MIT License.
