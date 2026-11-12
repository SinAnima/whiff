# mise

`whiff` is not in the built-in mise registry. Use the GitHub backend:

```bash
mise use -g github:baoulo/whiff@0.8.0
```

Or in `mise.toml`:

```toml
[tools]
"github:baoulo/whiff" = "0.8.0"
```

To keep a short name in `.tool-versions` (`whiff 0.8.0`):

```toml
[tool_alias]
whiff = "github:baoulo/whiff"
```

If multiple assets match, narrow with `matching = "whiff-"`.
