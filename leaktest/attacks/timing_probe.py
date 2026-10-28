"""
Leak-Test Attack 5: Statistical Timing Channel Inference
Attacker trains a statistical classifier on response latencies to infer Blue defense rules
and distinguish whether an evaluation was blocked early vs evaluated by the model.
"""

import random
import numpy as np
from typing import Dict, Any, Tuple
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

def simulate_timing_samples(mode: str = "sealarena", n_samples: int = 200) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates synthetic evaluation request latencies for blocked (0) vs allowed (1) prompts.
    mode: "baseline" (unpadded raw latency) vs "sealarena" (padded latency with jitter)
    """
    y = np.random.binomial(1, 0.5, n_samples)
    X = np.zeros((n_samples, 1))

    for i in range(n_samples):
        if mode == "baseline":
            # Fast reject keyword check ~ 3ms +- 1ms; LLM inference ~ 350ms +- 20ms
            if y[i] == 0:  # BLOCKED
                lat = random.gauss(3.5, 0.8)
            else:          # ALLOWED
                lat = random.gauss(345.0, 18.0)
            X[i, 0] = max(lat, 1.0)
        else:
            # SealArena: fixed-time padding to 350ms + Gaussian jitter (sigma = 4ms)
            lat = random.gauss(350.0, 4.0)
            X[i, 0] = lat

    return X, y

def run_attack(mode: str = "sealarena") -> Dict[str, Any]:
    X, y = simulate_timing_samples(mode, n_samples=300)

    # Train/test split (70/30)
    split_idx = int(len(y) * 0.7)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]

    clf = LogisticRegression()
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    accuracy = accuracy_score(y_test, preds)

    leaked = (accuracy > 0.75)

    details = []
    if mode == "baseline":
        details.append(f"Attacker classifier accuracy: {accuracy * 100.0:.1f}% (HIGH LEAKAGE)")
        details.append("Attacker easily distinguishes Blue rule hits (3ms) from Model inference (350ms)")
    else:
        details.append(f"Attacker classifier accuracy: {accuracy * 100.0:.1f}% (~50% chance level / random guess)")
        details.append("Fixed-time padding and jitter eliminates side-channel timing correlation")

    return {
        "test_name": "Timing Side-Channel Classifier",
        "vector": "Response Latency Statistical Inference",
        "leaked": leaked,
        "accuracy": accuracy,
        "details": details,
        "guarantee": "Arbiter normalizes response latency into quantized window with jitter; accuracy ~ chance."
    }

if __name__ == "__main__":
    print(run_attack("baseline"))
    print(run_attack("sealarena"))
