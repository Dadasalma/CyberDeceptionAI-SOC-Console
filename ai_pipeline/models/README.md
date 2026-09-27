# Model artifacts

Model binaries are intentionally not committed in this public repository.

Train/export the Random Forest bundle with:

```bash
cd ai_pipeline
pip install -r requirements.txt
TRAINING_DATASET=/path/to/dataset_ia.jsonl python module2_classification.py
```

The script writes `models/model_extended.pkl`, which is the bundle expected by `run_pipeline.py`.

> `pickle` files should only be loaded when you trust their source.
