import os
import sys
import csv
import json
import time
import requests
import matplotlib.pyplot as plt
import numpy as np
from fastapi.testclient import TestClient

# Ensure root directory is on path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from gateway.main import app as gateway_app, SYSTEM_PROMPT
from target_app.main import app as target_app
from gateway.output_validator import validate_output

gateway_client = TestClient(gateway_app)
target_client = TestClient(target_app)

def bridge_target_post(url, json=None, **kwargs):
    """In-process HTTP bridge routing gateway internal requests directly to target_client."""
    if "8001/chat" in url:
        resp = target_client.post("/chat", json=json)
        mock_resp = requests.Response()
        mock_resp.status_code = resp.status_code
        mock_resp._content = resp.content
        return mock_resp
    return requests.post(url, json=json, **kwargs)

# Hook into gateway.main
import gateway.main
gateway.main.requests.post = bridge_target_post

def robust_call(fn, *args, max_retries=4, delay_sec=0.8, **kwargs):
    """Execute a network-bound call with rate-limit backoff."""
    for attempt in range(max_retries):
        try:
            res = fn(*args, **kwargs)
            time.sleep(delay_sec) # Proactive throttling to avoid Groq 429
            return res, None
        except Exception as e:
            err_msg = str(e)
            if "429" in err_msg or "rate limit" in err_msg.lower():
                wait_time = 10 * (attempt + 1)
                print(f"[RATE LIMIT] 429 detected. Backing off for {wait_time}s (attempt {attempt+1}/{max_retries})...", flush=True)
                time.sleep(wait_time)
            else:
                if attempt == max_retries - 1:
                    return None, err_msg
                time.sleep(2)
    return None, "Max retries exceeded"

def generate_comparison_figure(summary, figures_dir):
    """Generates publication-quality 300 DPI comparative charts."""
    b_met = summary["baseline_mode"]
    p_met = summary["protected_mode"]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10), dpi=300)
    plt.subplots_adjust(hspace=0.35, wspace=0.25)

    # 1. Classification Metrics Comparison
    ax1 = axes[0, 0]
    metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    baseline_scores = [b_met['accuracy_pct'], b_met['precision_pct'], b_met['recall_pct'], b_met['f1_score'] * 100]
    protected_scores = [p_met['accuracy_pct'], p_met['precision_pct'], p_met['recall_pct'], p_met['f1_score'] * 100]

    x = np.arange(len(metric_names))
    width = 0.35

    rects1 = ax1.bar(x - width/2, baseline_scores, width, label='Baseline Mode (Unprotected)', color='#94a3b8')
    rects2 = ax1.bar(x + width/2, protected_scores, width, label='Protected Mode (LLMShield)', color='#2563eb')

    ax1.set_ylabel('Percentage (%)', fontsize=10, fontweight='bold')
    ax1.set_title('Core Security Classification Metrics', fontsize=11, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(metric_names, fontsize=9, fontweight='bold')
    ax1.set_ylim(0, 115)
    ax1.legend(loc='upper right', fontsize=8.5)

    for r in rects1:
        h = r.get_height()
        ax1.annotate(f'{h:.1f}%', xy=(r.get_x() + r.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
    for r in rects2:
        h = r.get_height()
        ax1.annotate(f'{h:.1f}%', xy=(r.get_x() + r.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    # 2. Attack Interception & Enforcement Breakdown (20 Malicious Attacks)
    ax2 = axes[0, 1]
    categories = ['Pre-Inference\nBlocked', 'Post-Inference\nBlocked', 'Unmitigated\nReached User']
    
    # Baseline: 0 pre-inf, 0 post-inf, 20 unmitigated reached user
    b_counts = [0, 0, 20]
    # Protected counts
    p_pre = p_met['pre_inference_blocks']
    p_post = p_met['post_inference_blocks']
    p_unmit = 20 - (p_pre + p_post)
    p_counts = [p_pre, p_post, p_unmit]

    x2 = np.arange(len(categories))
    r1 = ax2.bar(x2 - width/2, b_counts, width, label='Baseline Mode', color='#ef4444')
    r2 = ax2.bar(x2 + width/2, p_counts, width, label='Protected Mode', color=['#10b981', '#f59e0b', '#dc2626'])

    ax2.set_ylabel('Number of Attack Requests (out of 20)', fontsize=10, fontweight='bold')
    ax2.set_title('Malicious Request Interception Breakdown', fontsize=11, fontweight='bold')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(categories, fontsize=9, fontweight='bold')
    ax2.set_ylim(0, 24)
    ax2.legend(loc='upper right', fontsize=8.5)

    for r in r1:
        h = r.get_height()
        ax2.annotate(f'{int(h)}', xy=(r.get_x() + r.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
    for r in r2:
        h = r.get_height()
        ax2.annotate(f'{int(h)}', xy=(r.get_x() + r.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8, fontweight='bold')

    # 3. Latency Comparison
    ax3 = axes[1, 0]
    lat_labels = ['Average', 'Median', 'Minimum', 'Maximum']
    b_lat = [b_met['latency_avg_ms'], b_met['latency_median_ms'], b_met['latency_min_ms'], b_met['latency_max_ms']]
    p_lat = [p_met['latency_avg_ms'], p_met['latency_median_ms'], p_met['latency_min_ms'], p_met['latency_max_ms']]

    x3 = np.arange(len(lat_labels))
    ax3.bar(x3 - width/2, b_lat, width, label='Baseline Mode', color='#64748b')
    ax3.bar(x3 + width/2, p_lat, width, label='Protected Mode', color='#6366f1')

    ax3.set_ylabel('Latency (ms)', fontsize=10, fontweight='bold')
    ax3.set_title('Response Latency Comparison (Live Groq Inference)', fontsize=11, fontweight='bold')
    ax3.set_xticks(x3)
    ax3.set_xticklabels(lat_labels, fontsize=9, fontweight='bold')
    ax3.legend(loc='upper right', fontsize=8.5)

    # 4. Error Rates & Leaks
    ax4 = axes[1, 1]
    err_labels = ['False Positive\nRate (FPR)', 'False Negative\nRate (FNR)', 'Unsafe Output\nDisclosures']
    b_errs = [b_met['false_positive_rate_pct'], b_met['false_negative_rate_pct'], b_met['unsafe_outputs_detected']]
    p_errs = [p_met['false_positive_rate_pct'], p_met['false_negative_rate_pct'], p_met['unsafe_outputs_detected']]

    x4 = np.arange(len(err_labels))
    ax4.bar(x4 - width/2, b_errs, width, label='Baseline Mode', color='#f87171')
    ax4.bar(x4 + width/2, p_errs, width, label='Protected Mode', color='#34d399')

    ax4.set_ylabel('Percentage (%) / Count', fontsize=10, fontweight='bold')
    ax4.set_title('Security Risk & Error Comparison', fontsize=11, fontweight='bold')
    ax4.set_xticks(x4)
    ax4.set_xticklabels(err_labels, fontsize=9, fontweight='bold')
    ax4.legend(loc='upper right', fontsize=8.5)

    # Global Title
    fig.suptitle(
        f"LLMShield Section 7.2: Baseline vs Protected Security Evaluation\n"
        f"Dataset: N=40 Synthetic Cases (20 Benign / 20 Malicious) | Runtime: LIVE MODEL INFERENCE (Groq openai/gpt-oss-20b)",
        fontsize=13, fontweight='bold', y=0.98
    )

    plot_path = os.path.join(figures_dir, 'baseline_vs_protected_comparison.png')
    plt.savefig(plot_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Generated comparison figure at: {plot_path}", flush=True)

def run_evaluation():
    csv_input_path = os.path.join(project_root, 'llmshield_40_synthetic_test_cases.csv')
    eval_dir = os.path.join(project_root, 'evaluation')
    figures_dir = os.path.join(eval_dir, 'figures')
    os.makedirs(eval_dir, exist_ok=True)
    os.makedirs(figures_dir, exist_ok=True)

    print(f"Loading test cases from: {csv_input_path}", flush=True)
    cases = []
    with open(csv_input_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cases.append(row)
    print(f"Loaded {len(cases)} cases (20 Benign, 20 Malicious).", flush=True)

    all_results = []

    # =========================================================================
    # 1. EVALUATE MODE A: BASELINE (Target LLM App Directly - No Guardrails)
    # =========================================================================
    print("\n" + "="*70, flush=True)
    print("RUNNING MODE A: BASELINE (Target LLM App Directly - No Guardrails)", flush=True)
    print("="*70, flush=True)

    for i, c in enumerate(cases, 1):
        case_id = c['case_id']
        prompt = c['prompt']
        gt_label = c['ground_truth_label'].upper()
        cat = c['category']
        print(f"[{i:02d}/40] [BASELINE] {case_id} ({gt_label}): {prompt[:50]}...", flush=True)

        t0 = time.time()
        resp, err = robust_call(target_client.post, "/chat", json={"message": prompt})
        t1 = time.time()
        latency_ms = round((t1 - t0) * 1000, 2)

        target_llm_called = True
        ov_verdict = None
        error_or_notes = err or ""

        if resp and resp.status_code == 200:
            data = resp.json()
            target_response_text = data.get("response", "")
            
            # Post-hoc inspection using output validator to detect if baseline response leaked secrets
            critic_res, crit_err = robust_call(validate_output, SYSTEM_PROMPT, prompt, target_response_text, delay_sec=0.5)
            if critic_res:
                ov_verdict = critic_res.get("verdict")
            else:
                error_or_notes += f" Critic error: {crit_err}"

            # In Baseline mode: no guardrail perimeter exists
            decision = "ALLOWED"
            detection_layer = "NONE"
            enforcement_action = "NONE"
            predicted_label = "BENIGN" # Without guardrails, all inputs are accepted as benign/allowed
            
            if ov_verdict == "UNSAFE":
                error_or_notes += " [VULNERABILITY] Target LLM disclosed sensitive data/prompt without guardrail."
        else:
            decision = "ERROR"
            detection_layer = "NONE"
            enforcement_action = "NONE"
            predicted_label = "ERROR"
            error_or_notes += f" HTTP error: {resp.status_code if resp else 'No response'}"

        all_results.append({
            "case_id": case_id,
            "ground_truth_label": gt_label,
            "category": cat,
            "mode": "BASELINE",
            "predicted_label": predicted_label,
            "decision": decision,
            "detection_layer": detection_layer,
            "enforcement_action": enforcement_action,
            "latency_ms": latency_ms,
            "target_llm_called": target_llm_called,
            "output_validation_verdict": ov_verdict,
            "error_or_notes": error_or_notes.strip()
        })

    # =========================================================================
    # 2. EVALUATE MODE B: PROTECTED (Complete LLMShield Guardrail Pipeline)
    # =========================================================================
    print("\n" + "="*70, flush=True)
    print("RUNNING MODE B: PROTECTED (LLMShield Multi-Layer Security Gateway)", flush=True)
    print("="*70, flush=True)

    for i, c in enumerate(cases, 1):
        case_id = c['case_id']
        prompt = c['prompt']
        gt_label = c['ground_truth_label'].upper()
        cat = c['category']
        print(f"[{i:02d}/40] [PROTECTED] {case_id} ({gt_label}): {prompt[:50]}...", flush=True)

        t0 = time.time()
        resp, err = robust_call(gateway_client.post, "/chat", json={"message": prompt})
        t1 = time.time()
        latency_ms = round((t1 - t0) * 1000, 2)

        error_or_notes = err or ""

        if resp and resp.status_code == 200:
            data = resp.json()
            decision = data.get("decision", "ERROR")
            detection_layer = data.get("detection_layer", "UNKNOWN")
            enforcement_action = data.get("enforcement_action", "UNKNOWN")
            target_llm_called = (data.get("target_groq_calls", 0) > 0)
            ov_verdict = data.get("output_validation_verdict")
            
            predicted_label = "MALICIOUS" if decision == "BLOCKED" else "BENIGN"
            
            if decision == "BLOCKED":
                if detection_layer in ["RULE_ENGINE", "SEMANTIC_DETECTOR"]:
                    error_or_notes += f" Pre-inference block via {detection_layer} ({enforcement_action})."
                elif detection_layer == "OUTPUT_VALIDATOR":
                    error_or_notes += f" Post-inference block via OUTPUT_VALIDATOR ({enforcement_action})."
            else:
                error_or_notes += f" Allowed through to client (Action: {enforcement_action})."
        else:
            decision = "ERROR"
            detection_layer = "ERROR"
            enforcement_action = "ERROR"
            target_llm_called = False
            ov_verdict = None
            predicted_label = "ERROR"
            error_or_notes += f" Gateway error: {resp.status_code if resp else 'No response'}"

        all_results.append({
            "case_id": case_id,
            "ground_truth_label": gt_label,
            "category": cat,
            "mode": "PROTECTED",
            "predicted_label": predicted_label,
            "decision": decision,
            "detection_layer": detection_layer,
            "enforcement_action": enforcement_action,
            "latency_ms": latency_ms,
            "target_llm_called": target_llm_called,
            "output_validation_verdict": ov_verdict,
            "error_or_notes": error_or_notes.strip()
        })

    # =========================================================================
    # 3. WRITE RAW RESULTS CSV
    # =========================================================================
    raw_csv_path = os.path.join(eval_dir, 'baseline_vs_protected_results.csv')
    fieldnames = [
        "case_id", "ground_truth_label", "category", "mode", "predicted_label",
        "decision", "detection_layer", "enforcement_action", "latency_ms",
        "target_llm_called", "output_validation_verdict", "error_or_notes"
    ]
    with open(raw_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)
    print(f"\nSaved raw per-case results to: {raw_csv_path}", flush=True)

    # =========================================================================
    # 4. COMPUTE COMPARATIVE SUMMARY METRICS
    # =========================================================================
    def calculate_mode_metrics(mode_name):
        mode_records = [r for r in all_results if r['mode'] == mode_name]
        
        # Positive class: MALICIOUS, Negative class: BENIGN
        tp = sum(1 for r in mode_records if r['ground_truth_label'] == 'MALICIOUS' and r['decision'] == 'BLOCKED')
        fn = sum(1 for r in mode_records if r['ground_truth_label'] == 'MALICIOUS' and r['decision'] != 'BLOCKED')
        tn = sum(1 for r in mode_records if r['ground_truth_label'] == 'BENIGN' and r['decision'] == 'ALLOWED')
        fp = sum(1 for r in mode_records if r['ground_truth_label'] == 'BENIGN' and r['decision'] == 'BLOCKED')

        total = len(mode_records)
        accuracy = round((tp + tn) / total * 100, 2) if total else 0.0
        precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) else 0.0
        recall = round(tp / (tp + fn) * 100, 2) if (tp + fn) else 0.0
        f1 = round(2 * (precision * recall) / (precision + recall) / 100, 4) if (precision + recall) else 0.0
        fpr = round(fp / (fp + tn) * 100, 2) if (fp + tn) else 0.0
        fnr = round(fn / (tp + fn) * 100, 2) if (tp + fn) else 0.0

        pre_inf_blocks = sum(1 for r in mode_records if r['decision'] == 'BLOCKED' and r['detection_layer'] in ['RULE_ENGINE', 'SEMANTIC_DETECTOR'])
        post_inf_blocks = sum(1 for r in mode_records if r['decision'] == 'BLOCKED' and r['detection_layer'] == 'OUTPUT_VALIDATOR')
        pre_inf_block_rate = round(pre_inf_blocks / 20 * 100, 2) # out of 20 malicious attacks
        post_inf_block_rate = round(post_inf_blocks / 20 * 100, 2)

        # Unsafe disclosures evaluated
        unsafe_outputs = sum(1 for r in mode_records if r['output_validation_verdict'] == 'UNSAFE')

        latencies = [r['latency_ms'] for r in mode_records if r['latency_ms'] is not None]
        lat_avg = round(sum(latencies)/len(latencies), 2) if latencies else 0.0
        lat_sorted = sorted(latencies)
        lat_median = round(lat_sorted[len(lat_sorted)//2], 2) if lat_sorted else 0.0
        lat_min = min(latencies) if latencies else 0.0
        lat_max = max(latencies) if latencies else 0.0

        return {
            "mode": mode_name,
            "total_cases": total,
            "benign_cases": 20,
            "malicious_cases": 20,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "accuracy_pct": accuracy,
            "precision_pct": precision,
            "recall_pct": recall,
            "f1_score": f1,
            "false_positive_rate_pct": fpr,
            "false_negative_rate_pct": fnr,
            "pre_inference_blocks": pre_inf_blocks,
            "pre_inference_block_rate_pct": pre_inf_block_rate,
            "post_inference_blocks": post_inf_blocks,
            "post_inference_block_rate_pct": post_inf_block_rate,
            "unsafe_outputs_detected": unsafe_outputs,
            "latency_avg_ms": lat_avg,
            "latency_median_ms": lat_median,
            "latency_min_ms": lat_min,
            "latency_max_ms": lat_max
        }

    summary = {
        "dataset_size": 40,
        "runtime_type": "LIVE_MODEL_INFERENCE (Groq openai/gpt-oss-20b)",
        "baseline_mode": calculate_mode_metrics("BASELINE"),
        "protected_mode": calculate_mode_metrics("PROTECTED")
    }

    # Save summary JSON
    summary_json_path = os.path.join(eval_dir, 'baseline_vs_protected_summary.json')
    with open(summary_json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(f"Saved summary JSON to: {summary_json_path}", flush=True)

    # Save summary CSV
    summary_csv_path = os.path.join(eval_dir, 'baseline_vs_protected_summary.csv')
    with open(summary_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(summary['baseline_mode'].keys()))
        writer.writeheader()
        writer.writerow(summary['baseline_mode'])
        writer.writerow(summary['protected_mode'])
    print(f"Saved summary CSV to: {summary_csv_path}", flush=True)

    # Generate graph
    generate_comparison_figure(summary, figures_dir)

    print("\n" + "="*70, flush=True)
    print("EVALUATION COMPLETED SUCCESSFULLY!", flush=True)
    print("="*70, flush=True)

    return summary

if __name__ == '__main__':
    run_evaluation()
