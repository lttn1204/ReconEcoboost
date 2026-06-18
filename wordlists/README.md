# Wordlists

Drop your own wordlists here. The framework references them **by path** from
[../config/wordlists.yaml](../config/wordlists.yaml), so a tool automatically
uses whatever file sits at the configured path — no code change needed.

## Convention

```
wordlists/
  <tool>/
    <logical-name>.txt
```

- One subfolder per tool that consumes wordlists.
- Files are referenced by a **logical name** in `config/wordlists.yaml`
  (e.g. `directories`, `common`), which maps to a path here.
- To use your own list, either **replace the file contents** at the existing
  path, or point the config entry at a new file you add.

## Which tools use wordlists (v1)

| Tool | Folder | Logical names | Used by stage |
|---|---|---|---|
| ffuf | `ffuf/` | `directories`, `common` | `dir_bruteforce` |

The other v1 tools (subfinder, httpx, katana, gau, whatweb) do not take a
wordlist. When a future tool that does (e.g. a DNS brute-forcer) is added,
create a sibling folder `wordlists/<tool>/` and add its entry to
`config/wordlists.yaml`.

## Notes

- The shipped `.txt` files are **minimal starters** so scans work immediately —
  replace them with your real lists (SecLists, custom, etc.).
- Lines beginning with `#` are treated as comments (ffuf is run with `-ic`,
  "ignore comments"), so you can keep headers/notes in your files.
- Paths in `config/wordlists.yaml` are resolved relative to the directory you
  run `reconecoboost` from (the project root by default). Absolute paths also
  work if you prefer to keep wordlists elsewhere.
