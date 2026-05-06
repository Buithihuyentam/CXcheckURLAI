# threshold_optimization.py
"""
Tối ưu hóa Decision Threshold dựa trên business requirements

Mặc định, model sử dụng threshold = 0.5 (50% phishing probability)
Nhưng điều này có thể không tối ưu cho use case của bạn

Ví dụ:
- Security-first (Bank): Prefer high recall (catch all phishing) → threshold = 0.3
- User experience-first: Prefer high precision (avoid false alarms) → threshold = 0.7
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import (
    precision_recall_curve,
    roc_curve,
    f1_score,
    precision_score,
    recall_score
)


def optimize_threshold_f1(y_true, y_proba):
    """
    Tìm threshold tối ưu dựa trên F1-score
    (Cân bằng precision và recall)
    """
    
    precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
    
    # F1 = 2 * (precision * recall) / (precision + recall)
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
    
    # Tìm F1 max
    best_idx = np.argmax(f1_scores)
    best_threshold = thresholds[best_idx] if best_idx < len(thresholds) else 0.5
    best_f1 = f1_scores[best_idx]
    
    return best_threshold, best_f1


def optimize_threshold_business(y_true, y_proba, max_fpr=0.05, target_recall=0.90):
    """
    Tối ưu dựa trên business requirements
    
    Args:
        max_fpr: Tối đa false positive rate chấp nhận (default 5%)
        target_recall: Minimum recall muốn đạt (default 90%)
    
    Returns:
        Optimal threshold + metrics
    """
    
    # Tính FPR, TPR cho mỗi threshold
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    
    # Tìm threshold mà:
    # 1. FPR <= max_fpr
    # 2. TPR (recall) >= target_recall
    valid_idx = (fpr <= max_fpr) & (tpr >= target_recall)
    
    if valid_idx.any():
        best_idx = np.where(valid_idx)[0][np.argmax(tpr[valid_idx])]
        chosen_reason = 'both'
    else:
        print(f"[!] Không thể đạt cả conditions (FPR <= {max_fpr} & Recall >= {target_recall})")
        print("    Thử giảm target_recall hoặc tăng max_fpr")
        
        # Nếu không thể, chọn threshold tốt nhất thỏa FPR <= max_fpr
        fpr_ok = np.where(fpr <= max_fpr)[0]
        if len(fpr_ok) > 0:
            best_idx = fpr_ok[np.argmax(tpr[fpr_ok])]
            chosen_reason = 'fpr'
        else:
            # Nếu không có threshold nào thỏa FPR, chọn threshold tối ưu nhất theo recall
            best_idx = np.argmax(tpr)
            chosen_reason = 'recall'
    
    best_threshold = thresholds[best_idx]
    
    return best_threshold, {
        'fpr': fpr[best_idx],
        'tpr': tpr[best_idx],  # recall
        'threshold': best_threshold,
        'chosen_reason': chosen_reason
    }


def analyze_thresholds(y_true, y_proba, thresholds_to_test=None):
    """
    Phân tích chi tiết mỗi threshold
    """
    
    if thresholds_to_test is None:
        thresholds_to_test = np.arange(0.2, 0.91, 0.1)
    
    results = []
    
    for threshold in thresholds_to_test:
        y_pred = (y_proba >= threshold).astype(int)
        
        tp = np.sum((y_pred == 1) & (y_true == 1))
        fp = np.sum((y_pred == 1) & (y_true == 0))
        tn = np.sum((y_pred == 0) & (y_true == 0))
        fn = np.sum((y_pred == 0) & (y_true == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        results.append({
            'threshold': threshold,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'fpr': fpr,
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
        })
    
    return pd.DataFrame(results)


def visualize_threshold_analysis(y_true, y_proba):
    """Visualize metrics vs threshold"""
    
    results = analyze_thresholds(y_true, y_proba, 
                                 thresholds_to_test=np.arange(0.1, 0.95, 0.01))
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Subplot 1: Precision, Recall, F1 vs Threshold
    axes[0, 0].plot(results['threshold'], results['precision'], label='Precision', marker='o')
    axes[0, 0].plot(results['threshold'], results['recall'], label='Recall', marker='s')
    axes[0, 0].plot(results['threshold'], results['f1'], label='F1-Score', marker='^')
    axes[0, 0].axvline(x=0.5, color='red', linestyle='--', label='Default (0.5)')
    axes[0, 0].set_xlabel('Threshold')
    axes[0, 0].set_ylabel('Score')
    axes[0, 0].set_title('Metrics vs Threshold')
    axes[0, 0].legend()
    axes[0, 0].grid(alpha=0.3)
    
    # Subplot 2: FPR vs Threshold
    axes[0, 1].plot(results['threshold'], results['fpr'], marker='o', color='red')
    axes[0, 1].axhline(y=0.05, color='green', linestyle='--', label='Max acceptable FPR (5%)')
    axes[0, 1].set_xlabel('Threshold')
    axes[0, 1].set_ylabel('False Positive Rate')
    axes[0, 1].set_title('False Positive Rate vs Threshold')
    axes[0, 1].legend()
    axes[0, 1].grid(alpha=0.3)
    
    # Subplot 3: TP, FP, TN, FN vs Threshold
    axes[1, 0].plot(results['threshold'], results['tp'], label='TP', marker='o')
    axes[1, 0].plot(results['threshold'], results['fp'], label='FP', marker='s')
    axes[1, 0].plot(results['threshold'], results['tn'], label='TN', marker='^')
    axes[1, 0].plot(results['threshold'], results['fn'], label='FN', marker='d')
    axes[1, 0].set_xlabel('Threshold')
    axes[1, 0].set_ylabel('Count')
    axes[1, 0].set_title('Confusion Matrix Components vs Threshold')
    axes[1, 0].legend()
    axes[1, 0].grid(alpha=0.3)
    
    # Subplot 4: Precision-Recall Curve
    axes[1, 1].plot(results['recall'], results['precision'], marker='o', linewidth=2)
    axes[1, 1].set_xlabel('Recall')
    axes[1, 1].set_ylabel('Precision')
    axes[1, 1].set_title('Precision-Recall Curve')
    axes[1, 1].grid(alpha=0.3)
    axes[1, 1].set_xlim([0, 1])
    axes[1, 1].set_ylim([0, 1])
    
    plt.tight_layout()
    plt.savefig('threshold_analysis.png', dpi=150)
    print("[✓] Threshold analysis plot saved to threshold_analysis.png")
    
    return results


def main():
    """Example: Optimize threshold từ test set predictions"""
    
    # Simulated data (thay bằng real test set)
    np.random.seed(42)
    y_true = np.concatenate([np.zeros(100), np.ones(80)])
    y_proba = np.concatenate([
        np.random.beta(2, 5, 100),     # Legitimate URLs (lower proba)
        np.random.beta(5, 2, 80)       # Phishing URLs (higher proba)
    ])
    
    print("="*60)
    print("THRESHOLD OPTIMIZATION")
    print("="*60)
    
    # Strategy 1: F1-score optimization
    print("\n[STRATEGY 1] Optimize for F1-Score (balanced approach)")
    threshold_f1, best_f1 = optimize_threshold_f1(y_true, y_proba)
    print(f"  → Optimal threshold: {threshold_f1:.3f}")
    print(f"  → Best F1-score: {best_f1:.4f}")
    
    # Get metrics at this threshold
    y_pred = (y_proba >= threshold_f1).astype(int)
    print(f"  → Precision: {precision_score(y_true, y_pred):.4f}")
    print(f"  → Recall: {recall_score(y_true, y_pred):.4f}")
    
    # Strategy 2: Business-focused optimization
    print("\n[STRATEGY 2] Business-Focused (Max 5% FPR, Min 90% Recall)")
    threshold_biz, metrics_biz = optimize_threshold_business(
        y_true, y_proba, 
        max_fpr=0.05, 
        target_recall=0.90
    )
    print(f"  → Optimal threshold: {threshold_biz:.3f}")
    print(f"  → FPR: {metrics_biz['fpr']:.4f}")
    print(f"  → Recall: {metrics_biz['tpr']:.4f}")
    if metrics_biz.get('chosen_reason') != 'both':
        print(f"  → Note: selected threshold based on {metrics_biz['chosen_reason']} optimization, not both conditions")
    
    # Analyze all thresholds
    print("\n[STRATEGY 3] Detailed Threshold Analysis")
    print("\n  Threshold | Precision | Recall | F1-Score | FPR")
    print("  " + "-"*50)
    for _, row in analyze_thresholds(y_true, y_proba).iterrows():
        print(f"   {row['threshold']:.2f}     |   {row['precision']:.3f}   |  {row['recall']:.3f}  |  {row['f1']:.3f}  | {row['fpr']:.3f}")
    
    # Visualize
    print("\n[Generating visualization...]")
    results_detail = visualize_threshold_analysis(y_true, y_proba)
    
    print("\n" + "="*60)
    print("RECOMMENDATIONS")
    print("="*60)
    print(f"\nUse threshold = {threshold_f1:.3f} for balanced approach (F1-optimized)")
    print(f"Use threshold = {threshold_biz:.3f} for security-first approach")
    if metrics_biz.get('chosen_reason') == 'both':
        print(f"  → This will catch 90% of phishing with only 5% false alarms")
    else:
        print(f"  → This threshold is the best available under the current data; it may not satisfy both FPR and recall targets simultaneously.")
    

if __name__ == "__main__":
    main()
