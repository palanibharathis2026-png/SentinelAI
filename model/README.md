# SentinelAI trained model

| File | What it is |
|---|---|
| `sentinel_model.npz` | The trained model: all 200 Isolation Forest trees (every split feature and threshold), the Robust Distance medians and spreads, and the calibration values. Plain NumPy arrays, no pickle. |
| `model_card.json` | Readable summary: algorithms and parameters, the 13 features with what the model learned for each, training data details and test results. |

Both files are written every time the model is trained: when the API starts, or with `python backend/train_model.py`.

## Open and use the model

```python
import sys; sys.path.insert(0, "backend")
import numpy as np
from ml_detector import load_detector

model = load_detector("model/sentinel_model.npz")
print(len(model.forest.model.trees), "trees, trained on", model.trained_on, "sessions")

# One session as 13 features (see model_card.json for the order):
# 5 hours outside usual time, new device, new country, 25x downloads and data
session = np.array([[5, 0, 1, 1, 1, 8.5, 0, 3.2, 3.2, 1.0, 2.0, 2, 1]])
print("ML anomaly risk:", model.risk(session)[0])   # 0 = normal, 25 = top 5% of normal, 100 = extreme
```

## Retrain

```bash
cd backend
python train_model.py --check                 # synthetic dataset
python train_model.py --data my_logs.csv      # your own logs, same columns
```
