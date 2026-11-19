import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

def generate_flow_path_cfg():
    os.makedirs('evaluation/figures', exist_ok=True)
    
    fig, ax = plt.subplots(figsize=(18, 14), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 104)
    ax.axis('off')
    
    # Palette
    c_start = '#1e3a8a'     # Dark Blue
    c_proc = '#2563eb'      # Blue
    c_dec = '#d97706'       # Amber/Orange
    c_block = '#dc2626'     # Crimson Red
    c_allow = '#059669'     # Emerald Green
    c_log = '#4f46e5'       # Indigo
    
    def draw_node(x, y, w, h, title, subtitle="", node_type='rect', color=c_proc, text_color='white'):
        if node_type == 'oval':
            p = patches.FancyBboxPatch((x-w/2, y-h/2), w, h, boxstyle="round,pad=0.6,rounding_size=2.0",
                                       facecolor=color, edgecolor='#0f172a', linewidth=1.6, alpha=0.98)
            ax.add_patch(p)
        elif node_type == 'diamond':
            pts = [[x, y+h/2], [x+w/2, y], [x, y-h/2], [x-w/2, y]]
            p = patches.Polygon(pts, facecolor=color, edgecolor='#0f172a', linewidth=1.6, alpha=0.98)
            ax.add_patch(p)
        else: # rect
            p = patches.FancyBboxPatch((x-w/2, y-h/2), w, h, boxstyle="square,pad=0.3",
                                       facecolor=color, edgecolor='#0f172a', linewidth=1.6, alpha=0.98)
            ax.add_patch(p)
            
        tc = '#ffffff' if text_color == 'white' else '#0f172a'
        if subtitle:
            ax.text(x, y+0.9, title, ha='center', va='center', fontsize=8.5, fontweight='bold', color=tc)
            ax.text(x, y-1.1, subtitle, ha='center', va='center', fontsize=7.2, color=tc, alpha=0.95)
        else:
            ax.text(x, y, title, ha='center', va='center', fontsize=8.5, fontweight='bold', color=tc)

    def draw_arrow(x1, y1, x2, y2, label="", label_pos='right', color='#334155', ls='-'):
        ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color=color, lw=1.6, linestyle=ls, mutation_scale=12))
        if label:
            lx = (x1 + x2) / 2
            ly = (y1 + y2) / 2
            ox = 1.8 if 'right' in label_pos else (-1.8 if 'left' in label_pos else 0)
            oy = 1.1 if 'above' in label_pos else (-1.1 if 'below' in label_pos else 0)
            ax.text(lx + ox, ly + oy, label, ha='center', va='center', fontsize=7.2, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.2", facecolor='#ffffff', edgecolor='#cbd5e1', lw=0.8), color='#0f172a')

    # Title & Subtitle Banner
    ax.text(50, 101.5, "LLMShield Gateway Control Flow Graph (CFG) & Basis Path Mapping",
            ha='center', va='center', fontsize=15, fontweight='bold', color='#0f172a')
    ax.text(50, 99.0, "Basis Path Testing Suite: V(G) = E - N + 2P = 28 - 22 + 2(1) = 8 Linearly Independent Basis Paths",
            ha='center', va='center', fontsize=11, fontstyle='italic', color='#475569')

    # Metrics Summary Box
    metrics_box = patches.FancyBboxPatch((3, 85), 23, 14.5, boxstyle="square,pad=0.4",
                                         facecolor='#f8fafc', edgecolor='#94a3b8', lw=1.2)
    ax.add_patch(metrics_box)
    ax.text(14.5, 97.2, "CYCLOMATIC COMPLEXITY", ha='center', va='center', fontsize=8.5, fontweight='bold', color='#1e3a8a')
    ax.text(5, 94.5, "• Flow Graph Nodes (N): 22", fontsize=7.5, color='#334155')
    ax.text(5, 92.2, "• Flow Graph Edges (E): 28", fontsize=7.5, color='#334155')
    ax.text(5, 89.9, "• Predicate Deciders (π): 7", fontsize=7.5, color='#334155')
    ax.text(5, 87.6, "• Basis Paths: V(G) = 8", fontsize=8.0, fontweight='bold', color='#b91c1c')

    # -------------------------------------------------------------
    # Main Column (Center Spine x=50)
    # -------------------------------------------------------------
    # N1: Entry
    draw_node(50, 95, 17, 3.8, "N1: Start Endpoint", "HTTP POST /chat", 'oval', c_start)
    
    # N2: Normalization
    draw_node(50, 87, 21, 4.0, "N2: Normalization", "normalize_text(NFKD)", 'rect', c_proc)
    draw_arrow(50, 93.1, 50, 89.0)

    # N3: Rule Check
    draw_node(50, 78, 18, 5.2, "N3: Rule Check", "is_attack?", 'diamond', c_dec, 'black')
    draw_arrow(50, 85.0, 50, 80.6)

    # N4: Path 1: Rule Engine Block (Left Column x=18)
    draw_node(18, 78, 22, 4.2, "N4: Path 1: Rule Block", "BLOCK_INPUT (0 Groq)", 'oval', c_block)
    draw_arrow(41, 78, 29, 78, "True (Match)", 'above')

    # N5: Suspicion Check (Center x=50)
    draw_node(50, 68, 18, 5.2, "N5: Suspicion?", "is_suspicious?", 'diamond', c_dec, 'black')
    draw_arrow(50, 75.4, 50, 70.6, "False", 'left')

    # -------------------------------------------------------------
    # Semantic Inspection Sub-Pipeline (Right Column x=78 & Far Right x=91)
    # -------------------------------------------------------------
    # N6: Semantic Detector
    draw_node(76, 68, 19, 4.2, "N6: Semantic Detector", "security_groq_calls=1", 'rect', c_proc)
    draw_arrow(59, 68, 66.5, 68, "True (Keyword)", 'above')

    # N7: API Exception?
    draw_node(76, 59, 16, 5.0, "N7: API Timeout?", "Exception?", 'diamond', c_dec, 'black')
    draw_arrow(76, 65.9, 76, 61.5)

    # N8: Path 3: Semantic Fail (Far Right x=91, y=59)
    draw_node(91, 59, 15, 4.0, "N8: Path 3: Fail", "Fail-Closed Block", 'oval', c_block)
    draw_arrow(84, 59, 83.5, 59, "True", 'above')

    # N9: Semantic Verdict Attack?
    draw_node(76, 50, 16, 5.0, "N9: Attack Found?", "is_attack?", 'diamond', c_dec, 'black')
    draw_arrow(76, 56.5, 76, 52.5, "False", 'right')

    # N10: Path 2: Semantic Block (Far Right x=91, y=50)
    draw_node(91, 50, 15, 4.0, "N10: Path 2: Block", "Attacker Block", 'oval', c_block)
    draw_arrow(84, 50, 83.5, 50, "True", 'above')

    # -------------------------------------------------------------
    # Target Application Forwarding (Center Spine x=50)
    # -------------------------------------------------------------
    # N11: Forward Target
    draw_node(50, 48, 22, 4.2, "N11: Forward Target", "Structured Role Boundary", 'rect', c_proc)
    # Direct Heuristic Bypass from N5 (False)
    draw_arrow(50, 65.4, 50, 50.1, "False (Clean Fast-Path)", 'left')
    # Semantic Vetted Safe from N9 (False)
    draw_arrow(68, 50, 61, 48.5, "False (Safe)", 'above')

    # N12: Target Conn OK?
    draw_node(50, 39, 18, 5.2, "N12: Conn Success?", "HTTP 200 OK?", 'diamond', c_dec, 'black')
    draw_arrow(50, 45.9, 50, 41.6)

    # N13: Path 8: Target Outage (Right x=82, y=39)
    draw_node(82, 39, 21, 4.2, "N13: Path 8: Target Outage", "BLOCK_VALIDATION_FAILURE", 'oval', c_block)
    draw_arrow(59, 39, 71.5, 39, "Except (500/Conn)", 'above')

    # -------------------------------------------------------------
    # Output Validation / Critic (Center Spine x=50)
    # -------------------------------------------------------------
    # N14: Output Critic
    draw_node(50, 29, 22, 4.2, "N14: Output Critic", "validate_output() Critic", 'rect', c_proc)
    draw_arrow(50, 36.4, 50, 31.1, "Success", 'left')

    # N15: Critic Error?
    draw_node(50, 20, 18, 5.0, "N15: Critic Error?", "exception?", 'diamond', c_dec, 'black')
    draw_arrow(50, 26.9, 50, 22.5)

    # N16: Path 7: Critic Fail-Closed (Left x=18, y=20)
    draw_node(18, 20, 22, 4.2, "N16: Path 7: Critic Fail", "BLOCK_VALIDATION_FAILURE", 'oval', c_block)
    draw_arrow(41, 20, 29, 20, "True (Fail-Closed)", 'above')

    # N17: Unsafe Output Verdict?
    draw_node(76, 20, 16, 5.0, "N17: Output Verdict", "UNSAFE?", 'diamond', c_dec, 'black')
    draw_arrow(59, 20, 68, 20, "False (Healthy)", 'above')

    # N18: Path 6: Exfiltration Block (Far Right x=91, y=10)
    draw_node(91, 10, 15, 4.2, "N18: Path 6: Block", "BLOCK_OUTPUT", 'oval', c_block)
    draw_arrow(84, 20, 89, 12.1, "True (Leaked)", 'right')

    # N19: Validated Safe Allowed (Center x=50, y=10)
    draw_node(50, 10, 24, 4.2, "N19: Paths 4 & 5: Allowed", "ALLOW (Clean Response)", 'oval', c_allow)
    draw_arrow(76, 17.5, 62, 11.5, "False (Safe)", 'below')

    # -------------------------------------------------------------
    # Termination & Audit DB (Bottom Center x=50, y=2)
    # -------------------------------------------------------------
    draw_node(50, 2, 28, 3.8, "N20/21: DB Audit & Return", "RequestLog SQLite & ChatResponse", 'oval', c_log)
    draw_arrow(50, 7.9, 50, 3.9)

    # Connect blocked endpoints to Audit Rail
    # Left column blocks (N4, N16) to rail x=6
    ax.plot([7, 7], [78, 2], color='#94a3b8', lw=1.2, ls='--')
    ax.plot([7, 36], [2, 2], color='#94a3b8', lw=1.2, ls='--')
    draw_arrow(7, 78, 7, 78) # connector point
    ax.plot([7, 7], [20, 2], color='#94a3b8', lw=1.2, ls='--')
    ax.annotate('', xy=(7, 78), xytext=(7, 78), arrowprops=dict(arrowstyle="-", color='#94a3b8', lw=1.2))

    # Right column blocks (N8, N10, N13, N18) to rail x=98.5
    ax.plot([98.5, 98.5], [59, 2], color='#94a3b8', lw=1.2, ls='--')
    ax.plot([98.5, 64], [2, 2], color='#94a3b8', lw=1.2, ls='--')

    plt.tight_layout()
    plt.savefig('evaluation/figures/flow_path_testing_cfg.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("Clean Flow Path Testing CFG generated at evaluation/figures/flow_path_testing_cfg.png")

if __name__ == '__main__':
    generate_flow_path_cfg()
