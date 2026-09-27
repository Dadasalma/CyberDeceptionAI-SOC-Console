# Data sources expected by the dashboard

The console can consume any subset of these files from `SOC_DATA_DIR`:

| File | Role |
|---|---|
| `dataset_ia.jsonl` | frozen Wazuh/Suricata alert export |
| `dataset_ia_live.jsonl` | live alert feed |
| `session_tracker_output.json` | grouped sessions |
| `rf_predictions.csv` | classifier outputs |
| `isolation_forest_results.csv` | anomaly-analysis output |
| `kmeans_clusters.csv` | cluster output |
| `shap_importance.csv` | feature-importance output |
| `decision_engine_log.jsonl` | risk/decision log |
| `system.log` | optional text log |

When a source is unavailable, the dashboard uses a clearly-labelled demo fallback for that section. The public repository intentionally ships no real telemetry.
