import json
import subprocess
import sys
from pathlib import Path

MALICIOUS_VERDICTS = {"confirmed", "probable", "likely", "malicious", "suspicious"}
BENIGN_VERDICTS = {"benign", "unlikely", "clean", "false positive", "false_positive"}


def build_alert(indicator, indicator_type):
    if indicator_type == "url":
        return f"Endpoint attempted to download a payload from {indicator}"
    if indicator_type == "domain":
        return f"Internal host resolved and connected to {indicator}"
    return f"Firewall logged an outbound connection to {indicator} from an internal host"


def run_sentinel(alert):
    try:
        result = subprocess.run(["sentinel", alert], capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        print("ERROR: sentinel command not found. Activate the venv first.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("   -> timed out")
        return None
    out = result.stdout
    start = out.find("{")
    if start == -1:
        return None
    try:
        return json.loads(out[start:])
    except json.JSONDecodeError:
        return None


def classify(verdict):
    v = verdict.strip().lower()
    if v in MALICIOUS_VERDICTS:
        return "malicious"
    if v in BENIGN_VERDICTS:
        return "benign"
    return "unknown"


def main():
    eval_dir = Path(__file__).resolve().parent
    data = json.loads((eval_dir / "labeled_set.json").read_text())
    alerts = data["labeled_alerts"]
    tp = fp = tn = fn = unknown = 0
    rows = []
    for entry in alerts:
        indicator = entry["indicator"]
        truth = entry["ground_truth"]
        alert = build_alert(indicator, entry.get("indicator_type", "ip"))
        print(f"Running {entry['id']:<13} {indicator} ...", flush=True)
        vj = run_sentinel(alert)
        if vj is None:
            print("   -> no parseable output")
            unknown += 1
            rows.append({**entry, "verdict": None, "predicted": "error"})
            continue
        verdict = vj.get("verdict", "")
        tier = vj.get("confidence_tier")
        predicted = classify(verdict)
        print(f"   -> verdict={verdict!r} tier={tier} predicted={predicted} truth={truth}")
        rows.append({**entry, "verdict": verdict, "confidence_tier": tier, "predicted": predicted})
        if predicted == "unknown":
            unknown += 1
            continue
        if truth == "malicious" and predicted == "malicious":
            tp += 1
        elif truth == "benign" and predicted == "malicious":
            fp += 1
        elif truth == "benign" and predicted == "benign":
            tn += 1
        elif truth == "malicious" and predicted == "benign":
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    print("\n" + "=" * 50)
    print("CONFUSION MATRIX  (positive class = malicious)")
    print("=" * 50)
    print("                 predicted MAL   predicted BEN")
    print(f"actual MAL          TP = {tp:<3}        FN = {fn:<3}")
    print(f"actual BEN          FP = {fp:<3}        TN = {tn:<3}")
    print("-" * 50)
    print(f"Precision : {precision:.1%}")
    print(f"Recall    : {recall:.1%}")
    print(f"F1 score  : {f1:.1%}")
    if unknown:
        print(f"\n[!] {unknown} verdict(s) did not map. Check verdict strings above and update the sets at top.")
    (eval_dir / "results.json").write_text(json.dumps({"summary": {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown": unknown}, "details": rows}, indent=2))
    print(f"\nFull results written to {eval_dir / 'results.json'}")


if __name__ == "__main__":
    main()
