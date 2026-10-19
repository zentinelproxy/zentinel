# Multi-file configuration example

Splits one configuration across several files using Zentinel's `include`
directive. Useful when routes, upstreams and listeners are maintained by
different people or change at different rates.

```
example-multi-file/
├── zentinel.kdl          entry point: schema-version, system, limits, includes
├── listeners/
│   ├── http.kdl          plain HTTP listener
│   └── https.kdl         TLS listener
├── upstreams/backends.kdl upstream pools
└── routes/
    ├── api.kdl           /api routes
    └── static.kdl        catch-all route
```

Validate the whole tree, through its entry point or as a directory:

```bash
zentinel test --strict --config config/example-multi-file/zentinel.kdl
zentinel test --strict --config config/example-multi-file
```

Both read the same files. `--strict` checks every one of them for settings
that are being ignored, and names the file each finding is in.

## Loading a directory

`zentinel -c <dir>` (or `ZENTINEL_CONFIG=<dir>`) reads every `*.kdl` file
under the directory, recursively and in path order, as one configuration.
`run`, `test`, `lint`, `validate` and reloads (SIGHUP, and `auto-reload`,
which then watches the whole directory) all accept one.

- A file that another file of the directory includes is read once, through
  the `include`. This tree therefore loads the same either way; a directory of
  standalone files with no `include` at all (`conf.d` style) works too.
- Hidden files and directories (editor lock files, the `..data` links of a
  Kubernetes ConfigMap mount), `*.example.*` and `*.bak` files and
  `environments/` are skipped.
- The files use the ordinary configuration format. Bare top-level `route` or
  `server` nodes are rejected, as they are in a single file.

## How includes work

- `include "routes/*.kdl"` takes a glob, resolved **relative to the file
  containing the directive**.
- Included files contain ordinary top-level blocks (`routes { … }`,
  `upstreams { … }`), not fragments. They are merged into one configuration,
  so several files may each contribute a `routes` block.
- Includes are expanded recursively, and circular includes are detected and
  rejected.
- A glob matching no files warns rather than failing, so an empty
  `routes/` directory does not break startup.
- `include` only works when loading from a file or a directory. Parsing a
  KDL *string* rejects it, since there is no base path to resolve against.

## Ordering

Route matching does not depend on file order: more specific routes win, and
catch-all routes need `priority "low"`. `static.kdl` relies on that rather
than on being included last.
