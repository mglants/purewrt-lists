# Custom nfqws2 decoy blobs

Drop `.bin` fake-payload files here to bundle them into the published lists
release. `examples/blocklist.yaml` sets `strategies.blobs_dir: blobs`, so for
every candidate blob whose `file:` matches a name in this directory the builder:

1. copies the `.bin` into `dist/blobs/<file>`,
2. computes its sha256 and writes it into `zapret_candidates.json`.

The `build-lists` workflow uploads `dist/blobs/*` as release assets. On the
router, PureWRT's `ResolveBlob` downloads `<lists_base>/blobs/<file>` and
verifies it against the published sha256 before use.

Resolution order per blob (builder side): **this dir** → `blobs_base`/`url`
(remote fetch) → nothing (router resolves from its shipped zapret package,
e.g. `stun.bin`, `quic_initial_www_google_com.bin`).

To use a custom blob, reference its `name` in a candidate's `params`
(`--lua-desync=fake:blob=<name>` or `seqovl_pattern=<name>`) and declare it:

```yaml
    blobs:
      - {name: quic_dbankcloud, file: quic_initial_dbankcloud_ru.bin}
```

then place `quic_initial_dbankcloud_ru.bin` in this directory.
