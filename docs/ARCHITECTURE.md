# Architecture

This repository focuses on the **analyst-facing SOC / security analytics view** of the cyber-deception work.

```mermaid
flowchart LR
    A[Suricata telemetry] --> B[Wazuh / OpenSearch]
    B --> C[Alert collector]
    C --> D[Session tracker]
    D --> E[ML classification]
    E --> F[Risk / decision logic]
    B --> G[SOC Command Console]
    D --> G
    E --> G
    F --> G
    H[Optional analytics artifacts\nIsolation Forest / KMeans / SHAP] --> G
    F -. remote action disabled by default .-> I[Conpot profile control]
```

## Design intent

- **Console first:** the Streamlit dashboard is a read-only visualization layer.
- **Evidence-aware:** each source can be real or a clearly-labelled fallback.
- **Separation of concerns:** collection, sessionization, classification, decision logic and visualization are separate modules.
- **Public-safe defaults:** real credentials, private telemetry and lab IPs are not shipped; remote actions are disabled by default.
