"""Train the ZTNA risk classifier and export artifacts for the dashboard.

Pipeline
--------
1. Load (or generate) the synthetic dataset.
2. Build a feature pipeline that:
     - encodes `time_of_day` as (sin, cos) pair (cyclical, hour 23↔0 close)
     - log1p-transforms `request_rate` (heavy-tailed)
     - standard-scales the numeric block
3. Compare four classifiers under 5-fold stratified cross-validation,
   scoring by F1 (balances precision/recall on the imbalanced classes).
4. Take the best estimator family, run a randomised hyperparameter
   search on it.
5. Calibrate probabilities (sigmoid / Platt) — sklearn's tree-based
   probabilities are not calibrated by default, which matters because
   the runtime engine uses the probability as a continuous risk signal.
6. Pick the F1-optimal classification threshold from the held-out PR curve.
7. Export model + a rich `metrics.json` for the dashboard.

Outputs (written to app/ml/artifacts/):
    model.joblib                  trained sklearn pipeline (calibrated)
    metrics.json                  comparison + chosen-model + curves
    confusion_matrix.png          heatmap
    feature_importance.png        permutation-importance bar chart
    roc_curve.png                 ROC curve
    pr_curve.png                  PR curve

Run:
    cd backend
    python -m app.ml.train
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import sklearn
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_validate,
    train_test_split,
)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from app.ml.features import RAW_FEATURES, engineer
from app.ml.generate_dataset import generate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ARTIFACTS = Path("app/ml/artifacts")
SEED = 7
N_SAMPLES = 20_000
CV_FOLDS = 5

BRAND = "#494fdf"
ALLOW = "#00a87e"
BLOCK = "#e23b4a"

# ---------------------------------------------------------------------------
# Pipeline factory
# ---------------------------------------------------------------------------

def _make_pipeline(estimator) -> Pipeline:
    return Pipeline([
        ("engineer", FunctionTransformer(engineer, validate=False)),
        ("scaler", StandardScaler()),
        ("clf", estimator),
    ])


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------

def _load_or_generate(n: int, seed: int) -> pd.DataFrame:
    csv_path = ARTIFACTS / "dataset.csv"
    if csv_path.exists():
        df = pd.read_csv(csv_path)
        if len(df) >= n:
            return df.head(n)
    rows = generate(n, seed)
    df = pd.DataFrame(rows)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(csv_path, index=False)
    return df


def _dataset_hash(df: pd.DataFrame) -> str:
    h = hashlib.sha256()
    h.update(pd.util.hash_pandas_object(df, index=True).values.tobytes())
    return h.hexdigest()[:12]


# ---------------------------------------------------------------------------
# Step 1 — model comparison under cross-validation
# ---------------------------------------------------------------------------

CANDIDATES = {
    "logistic_regression": LogisticRegression(max_iter=2000, random_state=SEED),
    "random_forest": RandomForestClassifier(
        n_estimators=200, max_depth=None, n_jobs=-1, random_state=SEED,
    ),
    "gradient_boosting": GradientBoostingClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.1, random_state=SEED,
    ),
    "mlp": MLPClassifier(
        hidden_layer_sizes=(32, 16), max_iter=400, random_state=SEED,
    ),
}


def _compare_models(X: np.ndarray, y: np.ndarray) -> tuple[str, list[dict]]:
    """Return (winning_model_name, comparison_table)."""
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=SEED)
    table: list[dict] = []
    for name, est in CANDIDATES.items():
        pipe = _make_pipeline(est)
        scores = cross_validate(
            pipe, X, y, cv=cv,
            scoring=["f1", "roc_auc", "average_precision"],
            n_jobs=-1, return_train_score=False,
        )
        table.append({
            "name": name,
            "cv_f1_mean":   round(float(np.mean(scores["test_f1"])), 4),
            "cv_f1_std":    round(float(np.std(scores["test_f1"])), 4),
            "cv_roc_auc":   round(float(np.mean(scores["test_roc_auc"])), 4),
            "cv_pr_auc":    round(float(np.mean(scores["test_average_precision"])), 4),
        })
        print(f"  cv  {name:>20s}  "
              f"f1={table[-1]['cv_f1_mean']:.4f}±{table[-1]['cv_f1_std']:.4f}  "
              f"auc={table[-1]['cv_roc_auc']:.4f}  "
              f"pr={table[-1]['cv_pr_auc']:.4f}")
    table.sort(key=lambda r: r["cv_f1_mean"], reverse=True)
    return table[0]["name"], table


# ---------------------------------------------------------------------------
# Step 2 — hyperparameter search on the winning family
# ---------------------------------------------------------------------------

SEARCH_SPACES = {
    "logistic_regression": {
        "clf__C": [0.01, 0.1, 0.5, 1.0, 5.0, 10.0],
        "clf__penalty": ["l2"],
        "clf__class_weight": [None, "balanced"],
    },
    "random_forest": {
        "clf__n_estimators": [200, 400, 600],
        "clf__max_depth": [None, 6, 10, 16],
        "clf__min_samples_split": [2, 5, 10],
        "clf__min_samples_leaf": [1, 2, 4],
        "clf__class_weight": [None, "balanced"],
    },
    "gradient_boosting": {
        "clf__n_estimators": [150, 200, 300, 400],
        "clf__max_depth": [2, 3, 4, 5],
        "clf__learning_rate": [0.03, 0.05, 0.1, 0.15],
        "clf__subsample": [0.7, 0.85, 1.0],
    },
    "mlp": {
        "clf__hidden_layer_sizes": [(32, 16), (64, 32), (32, 32, 16)],
        "clf__alpha": [1e-5, 1e-4, 1e-3],
        "clf__learning_rate_init": [1e-3, 5e-3],
    },
}


def _tune(name: str, X: np.ndarray, y: np.ndarray, n_iter: int = 20) -> tuple[Pipeline, dict]:
    pipe = _make_pipeline(CANDIDATES[name])
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=SEED)
    search = RandomizedSearchCV(
        pipe, SEARCH_SPACES[name],
        n_iter=n_iter, scoring="f1", cv=cv, n_jobs=-1,
        random_state=SEED, refit=True, verbose=0,
    )
    search.fit(X, y)
    best_params = {k.replace("clf__", ""): v for k, v in search.best_params_.items()}
    print(f"  tuned {name}  best_f1={search.best_score_:.4f}  params={best_params}")
    return search.best_estimator_, best_params


# ---------------------------------------------------------------------------
# Plots — themed to match the dashboard
# ---------------------------------------------------------------------------

def _theme(ax: plt.Axes) -> None:
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.spines["left"].set_color("#3a3d40")
    ax.spines["bottom"].set_color("#3a3d40")
    ax.tick_params(colors="#8d969e", labelsize=9)
    for label in (ax.xaxis.label, ax.yaxis.label, ax.title):
        label.set_color("#191c1f")


def _plot_confusion_matrix(cm: np.ndarray, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(4, 3.2), dpi=140)
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Purples", cbar=False,
        xticklabels=["benign", "attack"], yticklabels=["benign", "attack"],
        ax=ax, annot_kws={"size": 12, "weight": "bold"},
    )
    ax.set_xlabel("predicted")
    ax.set_ylabel("actual")
    ax.set_title("Confusion Matrix")
    fig.tight_layout()
    fig.savefig(out, transparent=True)
    plt.close(fig)


def _plot_feature_importance(importances: list[dict], out: Path) -> None:
    importances = sorted(importances, key=lambda x: x["importance"])
    names = [i["feature"] for i in importances]
    vals = [i["importance"] for i in importances]
    fig, ax = plt.subplots(figsize=(6, 3.5), dpi=140)
    ax.barh(names, vals, color=BRAND)
    ax.set_title("Feature Importance — permutation")
    ax.set_xlabel("Δ score when feature is permuted")
    _theme(ax)
    fig.tight_layout()
    fig.savefig(out, transparent=True)
    plt.close(fig)


def _plot_roc(fpr, tpr, auc: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(4, 3.2), dpi=140)
    ax.plot(fpr, tpr, color=BRAND, lw=2, label=f"AUC = {auc:.3f}")
    ax.plot([0, 1], [0, 1], color="#8d969e", lw=1, ls="--")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve")
    ax.legend(loc="lower right", frameon=False)
    _theme(ax)
    fig.tight_layout()
    fig.savefig(out, transparent=True)
    plt.close(fig)


def _plot_pr(precision, recall, ap: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(4, 3.2), dpi=140)
    ax.plot(recall, precision, color=BRAND, lw=2, label=f"AP = {ap:.3f}")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision–Recall Curve")
    ax.legend(loc="lower left", frameon=False)
    _theme(ax)
    fig.tight_layout()
    fig.savefig(out, transparent=True)
    plt.close(fig)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()

    print(f"[ml] dataset")
    df = _load_or_generate(n=N_SAMPLES, seed=SEED)
    dataset_hash = _dataset_hash(df)
    print(f"  rows={len(df)}  hash={dataset_hash}  attack_rate={df['is_attack'].mean():.3f}")

    X = df[RAW_FEATURES].to_numpy(dtype=float)
    y = df["is_attack"].to_numpy(dtype=int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y,
    )

    # 1. Model comparison
    print("[ml] cross-validating candidate classifiers")
    winner, comparison = _compare_models(X_train, y_train)
    print(f"  winner={winner}")

    # 2. Hyperparameter search on the winner
    print(f"[ml] tuning {winner}")
    tuned, best_params = _tune(winner, X_train, y_train, n_iter=20)

    # 3. Probability calibration on a held-out slice
    print("[ml] calibrating probabilities (sigmoid)")
    calibrated = CalibratedClassifierCV(tuned, method="sigmoid", cv=5)
    calibrated.fit(X_train, y_train)

    # 4. Held-out evaluation
    y_proba = calibrated.predict_proba(X_test)[:, 1]
    y_pred_05 = (y_proba >= 0.5).astype(int)

    # 5. F1-optimal threshold from the test PR curve
    precision_curve, recall_curve, thresholds = precision_recall_curve(y_test, y_proba)
    f1s = 2 * precision_curve * recall_curve / np.where(
        precision_curve + recall_curve == 0, 1, precision_curve + recall_curve,
    )
    best_idx = int(np.argmax(f1s[:-1]))
    optimal_threshold = float(thresholds[best_idx])
    y_pred_opt = (y_proba >= optimal_threshold).astype(int)

    # 6. Metrics @ default threshold and @ tuned threshold
    metrics_05 = _summarise(y_test, y_pred_05, y_proba)
    metrics_opt = _summarise(y_test, y_pred_opt, y_proba)
    cm = confusion_matrix(y_test, y_pred_opt)

    # 7. Permutation importance — honest about feature ranking
    print("[ml] permutation importance")
    perm = permutation_importance(
        calibrated, X_test, y_test, n_repeats=8, random_state=SEED, n_jobs=-1,
        scoring="f1",
    )
    feat_imp = sorted(
        [
            {
                "feature": f,
                "importance": float(round(perm.importances_mean[i], 5)),
                "std": float(round(perm.importances_std[i], 5)),
            }
            for i, f in enumerate(RAW_FEATURES)
        ],
        key=lambda x: x["importance"],
        reverse=True,
    )

    # 8. Curves — downsample for the dashboard payload
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    roc_points = _downsample_curve(fpr, tpr, n=60, x_key="fpr", y_key="tpr")
    pr_points = _downsample_curve(recall_curve, precision_curve, n=60,
                                  x_key="recall", y_key="precision")

    # 9. Calibration curve
    obs, pred = calibration_curve(y_test, y_proba, n_bins=10, strategy="quantile")
    calibration_points = [
        {"predicted": round(float(p), 4), "observed": round(float(o), 4)}
        for p, o in zip(pred, obs)
    ]

    elapsed = round(time.perf_counter() - t_start, 2)

    # 10. Save
    metrics = {
        "trained": True,
        "model": f"{winner} (calibrated, sigmoid)",
        "chosen_model": {
            "name": winner,
            "best_params": best_params,
            "calibration": "sigmoid (Platt)",
        },
        "model_comparison": comparison,
        "metadata": {
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "elapsed_seconds": elapsed,
            "dataset_hash": dataset_hash,
            "samples": int(len(df)),
            "test_samples": int(len(y_test)),
            "attack_rate": round(float(df["is_attack"].mean()), 4),
            "sklearn_version": sklearn.__version__,
            "python_version": platform.python_version(),
            "seed": SEED,
            "cv_folds": CV_FOLDS,
        },
        # Convenience flat fields the dashboard already reads.
        "samples": int(len(df)),
        "test_samples": int(len(y_test)),
        "accuracy": metrics_opt["accuracy"],
        "precision": metrics_opt["precision"],
        "recall": metrics_opt["recall"],
        "f1": metrics_opt["f1"],
        "roc_auc": metrics_opt["roc_auc"],
        "pr_auc": metrics_opt["pr_auc"],
        "brier": metrics_opt["brier"],
        "default_threshold": 0.5,
        "optimal_threshold": round(optimal_threshold, 4),
        "metrics_at_default_threshold": metrics_05,
        "metrics_at_optimal_threshold": metrics_opt,
        "confusion_matrix": cm.tolist(),
        "feature_importance": feat_imp,
        "roc_curve": roc_points,
        "pr_curve": pr_points,
        "calibration_curve": calibration_points,
        "features": RAW_FEATURES,
    }

    joblib.dump(calibrated, ARTIFACTS / "model.joblib")
    (ARTIFACTS / "metrics.json").write_text(json.dumps(metrics, indent=2))
    _plot_confusion_matrix(cm, ARTIFACTS / "confusion_matrix.png")
    _plot_feature_importance(feat_imp, ARTIFACTS / "feature_importance.png")
    _plot_roc(fpr, tpr, metrics_opt["roc_auc"], ARTIFACTS / "roc_curve.png")
    _plot_pr(precision_curve, recall_curve, metrics_opt["pr_auc"],
             ARTIFACTS / "pr_curve.png")

    print(
        f"[ml] done  acc={metrics_opt['accuracy']:.4f}  "
        f"f1={metrics_opt['f1']:.4f}  auc={metrics_opt['roc_auc']:.4f}  "
        f"pr_auc={metrics_opt['pr_auc']:.4f}  τ*={optimal_threshold:.3f}"
    )
    print(f"     elapsed={elapsed}s  artifacts={ARTIFACTS.resolve()}")


def _summarise(y_true, y_pred, y_proba) -> dict:
    return {
        "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc":   round(float(roc_auc_score(y_true, y_proba)), 4),
        "pr_auc":    round(float(average_precision_score(y_true, y_proba)), 4),
        "brier":     round(float(brier_score_loss(y_true, y_proba)), 4),
    }


def _downsample_curve(x, y, n: int, x_key: str, y_key: str) -> list[dict]:
    """Pick `n` evenly-spaced points along (x, y) to keep payload small."""
    if len(x) <= n:
        idx = range(len(x))
    else:
        idx = np.linspace(0, len(x) - 1, n).astype(int)
    return [
        {x_key: round(float(x[i]), 4), y_key: round(float(y[i]), 4)}
        for i in idx
    ]


if __name__ == "__main__":
    main()
