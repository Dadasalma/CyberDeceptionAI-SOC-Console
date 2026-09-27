# Scope and limitations

This repository represents the **V1 SOC / security analytics console** and supporting pipeline prototype.

- The dashboard is **read-only**. It visualizes artifacts; it does not itself execute Suricata, Wazuh, Conpot, Isolation Forest, KMeans or SHAP.
- The analyst-assistant panel in V1 is **rule-based**, not an LLM.
- Health/status indicators in the dashboard are configuration/manual status, not live probes of Wazuh or Conpot.
- Remote Conpot actions are **disabled by default** in the public version (`ENABLE_REMOTE_ACTIONS=0`).
- No real credentials, private lab telemetry, binary model files or original internal IP addresses are included.
- The ML classifier is a prototype built from the available Wazuh/Suricata alert schema; its outputs should not be treated as a production security control.

The goal is to demonstrate how security telemetry, ML outputs and decision context can be brought together in one analyst-facing interface.
