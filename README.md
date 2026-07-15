# dune-sdk

## Install

```bash
pip install dune-sdk
```

The import name is `dune`:

```python
from dune import Dune, SandboxParams
```

## Configure

The client reads its endpoints and key from the environment (or pass a
`DuneConfig` explicitly):

```bash
export DUNE_API_URL=https://...       # control plane
export DUNE_PROXY_URL=https://...     # data plane (exec / fs)
export DUNE_API_KEY=...               # bearer token
export DUNE_NAMESPACE=default         # logical grouping bucket
```

## License

Apache-2.0. See [LICENSE](LICENSE).
