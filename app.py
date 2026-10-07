"""
UPI Shield: inline fraud mitigation for UPI payments.
Run:  streamlit run app.py
"""
import os
import html
import hashlib
import secrets
from datetime import time as dtime

import pandas as pd
import streamlit as st

import engine

st.set_page_config(page_title="UPI Shield", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

PAGES = ["Home", "Dashboard", "Fraud Detection", "Settings"]

# =============================================================================
# THEME (real light / dark switching through CSS variables)
# =============================================================================
PALETTE = {
    "light": dict(bg="#FFFFFF", surface="#F8FAFC", card="#FFFFFF", border="#E2E8F0", text="#0F172A",
                  muted="#64748B", accent="#E11D48", link="#2563EB", shadow="rgba(15,23,42,.06)",
                  ok_bg="#ECFDF5", ok_bd="#10B981", ok_tx="#047857",
                  warn_bg="#FFFBEB", warn_bd="#F59E0B", warn_tx="#B45309",
                  bad_bg="#FEF2F2", bad_bd="#EF4444", bad_tx="#B91C1C",
                  info_bg="#EFF6FF", info_bd="#93C5FD", info_tx="#1E3A8A"),
    "dark": dict(bg="#0B1220", surface="#111A2E", card="#0F1729", border="#27344F", text="#E6EDF7",
                 muted="#9AA9C2", accent="#F43F5E", link="#60A5FA", shadow="rgba(0,0,0,.45)",
                 ok_bg="#062A1E", ok_bd="#10B981", ok_tx="#6EE7B7",
                 warn_bg="#2B2008", warn_bd="#F59E0B", warn_tx="#FCD34D",
                 bad_bg="#2D0F14", bad_bd="#EF4444", bad_tx="#FCA5A5",
                 info_bg="#0E1E3D", info_bd="#3B82F6", info_tx="#BFDBFE"),
}

STATIC_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
html, body, .stApp, .stMarkdown, label, input, textarea, button p, [data-baseweb="tab"] p
{ font-family: 'Plus Jakarta Sans', system-ui, -apple-system, 'Segoe UI', sans-serif; }
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"], [data-testid="stHeader"] { background: var(--bg); color: var(--text); }
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6, .stApp p, .stApp li, .stApp label,
.stApp [data-testid="stWidgetLabel"] p, [data-testid="stMarkdownContainer"] p { color: var(--text) !important; }
.stApp [data-testid="stCaptionContainer"] p, .stApp small { color: var(--muted) !important; }
.stApp hr { border-color: var(--border); }
code { background: var(--surface) !important; color: var(--text) !important; }
a { color: var(--link); }

section[data-testid="stSidebar"], section[data-testid="stSidebar"] > div { background: var(--surface) !important; }
section[data-testid="stSidebar"] { border-right: 1px solid var(--border); }
section[data-testid="stSidebar"] div[role="radiogroup"] label { padding: 6px 10px; border-radius: 10px; }
section[data-testid="stSidebar"] div[role="radiogroup"] label p { font-size: 1.1rem; font-weight: 700; }

div[data-baseweb="input"], div[data-baseweb="base-input"], div[data-baseweb="select"] > div, div[data-baseweb="textarea"]
{ background: var(--card) !important; border-color: var(--border) !important; border-radius: 10px !important; }
input, textarea { color: var(--text) !important; -webkit-text-fill-color: var(--text) !important; background: transparent !important; }
div[data-baseweb="select"] div, div[data-baseweb="select"] span { color: var(--text) !important; }
[data-testid="stNumberInputStepDown"], [data-testid="stNumberInputStepUp"] { background: var(--surface) !important; color: var(--text) !important; }
div[data-baseweb="popover"] > div, ul[role="listbox"], li[role="option"] { background: var(--card) !important; color: var(--text) !important; }
li[role="option"]:hover, li[aria-selected="true"] { background: var(--surface) !important; }
[data-testid="stFileUploaderDropzone"] { background: var(--surface) !important; border: 1px dashed var(--border) !important; }
[data-testid="stFileUploaderDropzone"] * { color: var(--text) !important; }

button[data-baseweb="tab"] p { color: var(--muted) !important; font-weight: 700; font-size: 1.02rem; }
button[data-baseweb="tab"][aria-selected="true"] p { color: var(--accent) !important; }
div[data-baseweb="tab-highlight"] { background: var(--accent) !important; }
div[data-baseweb="tab-border"] { background: var(--border) !important; }
[data-testid="stExpander"] { background: var(--card) !important; border: 1px solid var(--border) !important; border-radius: 14px !important; }
[data-testid="stExpander"] details, [data-testid="stExpander"] summary { background: transparent !important; color: var(--text) !important; }

button[data-testid="stBaseButton-primary"], button[kind="primary"] { background: var(--accent) !important; border: none !important; border-radius: 12px !important; font-weight: 800 !important; }
button[data-testid="stBaseButton-primary"] p, button[kind="primary"] p { color: #FFFFFF !important; font-weight: 800; }
button[data-testid="stBaseButton-secondary"], button[kind="secondary"], a[data-testid="stBaseLinkButton-secondary"]
{ background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 12px !important; }
button[data-testid="stBaseButton-secondary"] p, button[kind="secondary"] p, a[data-testid="stBaseLinkButton-secondary"] p { color: var(--text) !important; font-weight: 700; }
button:disabled { opacity: .45 !important; }

.card { background: var(--card); border: 1px solid var(--border); border-radius: 18px; padding: 22px; margin: 0 0 18px 0; box-shadow: 0 6px 20px var(--shadow); }
.card-title { font-weight: 800; font-size: 1.25rem; color: var(--text); margin-bottom: 10px; }
.muted { color: var(--muted); }
.notice { border: 2px solid; border-radius: 16px; padding: 16px 20px; margin: 4px 0 16px 0; }
.nt { font-weight: 800; font-size: 1.2rem; margin-bottom: 4px; }
.nb { font-weight: 500; font-size: 1.0rem; line-height: 1.5; }
.chips { display: flex; flex-wrap: wrap; gap: 10px; margin: 0 0 14px 0; }
.chip { background: var(--card); border: 1px solid var(--border); border-radius: 20px; padding: 6px 14px; font-weight: 700; font-size: .92rem; color: var(--text); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin: 6px 0 18px 0; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 16px; }
.tl { font-size: .78rem; font-weight: 800; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin-bottom: 4px; }
.tv { font-size: 1.7rem; font-weight: 800; color: var(--text); }
.brow { display: grid; grid-template-columns: 150px 1fr 90px; align-items: center; gap: 10px; margin: 7px 0; font-size: .95rem; }
.brow .bl { color: var(--text); font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.brow .bt { background: var(--surface); border-radius: 8px; height: 16px; overflow: hidden; border: 1px solid var(--border); }
.brow .bf { height: 100%; border-radius: 8px; }
.brow .bv { color: var(--text); font-weight: 700; text-align: right; }
.tblwrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 14px; margin-bottom: 14px; }
.tbl { width: 100%; border-collapse: collapse; font-size: .92rem; }
.tbl th { text-align: left; background: var(--surface); color: var(--muted); font-weight: 800; padding: 10px 12px; white-space: nowrap; }
.tbl td { padding: 10px 12px; border-top: 1px solid var(--border); color: var(--text); white-space: nowrap; }
.pill { display: inline-block; border-radius: 999px; padding: 3px 12px; font-weight: 800; font-size: .82rem; border: 1px solid; }
.step { display: flex; justify-content: space-between; align-items: center; gap: 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 12px 16px; margin-bottom: 8px; }
.step .sn { font-weight: 800; color: var(--text); } .step .sd { color: var(--muted); font-size: .95rem; }
.sms { background: var(--surface); border: 1px solid var(--border); border-left: 5px solid var(--accent); border-radius: 12px; padding: 12px 16px; margin-bottom: 8px; color: var(--text); }
.codebox { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px; font-family: ui-monospace, 'JetBrains Mono', monospace; font-size: .88rem; color: var(--text); white-space: pre-wrap; overflow-x: auto; }
.hero { font-size: clamp(2.2rem, 5vw, 3.6rem); font-weight: 800; color: var(--text); letter-spacing: -1px; line-height: 1.1; }
.hero-sub { font-size: clamp(1.3rem, 3vw, 2rem); font-weight: 800; color: var(--text); margin: 10px 0 14px 0; }
.hero-p { font-size: 1.2rem; color: var(--muted); line-height: 1.7; margin-bottom: 22px; }
.feat-t { font-size: 1.35rem; font-weight: 800; color: var(--text); margin-bottom: 6px; }
.feat-p { font-size: 1.05rem; color: var(--muted); line-height: 1.6; }
.page-h { font-size: 2.1rem; font-weight: 800; color: var(--text); margin-bottom: 2px; }
.page-s { font-size: 1.05rem; color: var(--muted); margin-bottom: 18px; }
"""


def theme_css(theme):
    p = PALETTE[theme]
    root = ":root{" + "".join(f"--{k.replace('_', '-')}:{v};" for k, v in p.items()) + "}"
    return "<style>" + root + STATIC_CSS + "</style>"


# =============================================================================
# HTML helpers (single-line HTML so Markdown never turns it into a code block)
# =============================================================================
class Raw(str):
    """Marks a table cell as already-safe HTML."""


def esc(x):
    return html.escape(str(x))


def H(s):
    return "".join(line.strip() for line in s.strip().splitlines())


def md(s):
    st.markdown(H(s), unsafe_allow_html=True)


def notice(kind, title, body=""):
    md(f'<div class="notice" style="background:var(--{kind}-bg);border-color:var(--{kind}-bd)">'
       f'<div class="nt" style="color:var(--{kind}-tx)">{title}</div><div class="nb">{body}</div></div>')


def tiles(items):
    """items: (label, value, kind or None)"""
    cells = "".join(
        f'<div class="tile"><div class="tl">{esc(l)}</div>'
        f'<div class="tv" style="color:{"var(--%s-tx)" % k if k else "var(--text)"}">{esc(v)}</div></div>'
        for l, v, k in items)
    md(f'<div class="tiles">{cells}</div>')


def card(title, inner):
    return f'<div class="card"><div class="card-title">{title}</div>{inner}</div>'


def bar_html(items, color="--accent", fmt="{:,.0f}"):
    if not items:
        return '<div class="muted">No data yet.</div>'
    top = max(v for _, v in items) or 1
    return "".join(
        f'<div class="brow"><div class="bl" title="{esc(l)}">{esc(l)}</div>'
        f'<div class="bt"><div class="bf" style="width:{max(v / top * 100, 1.5):.1f}%;background:var({color})"></div></div>'
        f'<div class="bv">{fmt.format(v)}</div></div>' for l, v in items)


def table_html(rows, columns):
    head = "".join(f"<th>{esc(h)}</th>" for _, h in columns)
    body = ""
    for r in rows:
        cells = ""
        for k, _ in columns:
            v = r.get(k, "")
            cells += f"<td>{v if isinstance(v, Raw) else esc(v)}</td>"
        body += f"<tr>{cells}</tr>"
    if not rows:
        body = f'<tr><td colspan="{len(columns)}" class="muted">No rows.</td></tr>'
    return f'<div class="tblwrap"><table class="tbl"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def html_table(rows, columns):
    md(table_html(rows, columns))


STATUS_META = {"SUCCESS": ("ok", "Success"), "PENDING_OTP": ("warn", "OTP hold"), "EXPIRED": ("warn", "Expired"),
               "BLOCKED": ("bad", "Blocked"), "DECLINED": ("bad", "Declined")}
BANNER = {"SUCCESS": "✅ Payment successful", "PENDING_OTP": "⏸️ Payment held: OTP required",
          "BLOCKED": "🚫 Payment blocked before debit", "DECLINED": "❌ Payment declined",
          "EXPIRED": "⌛ Hold expired: nothing was debited"}
SIM_BANNER = {"TIER_1_PASS": ("ok", "✅ Would be approved"), "TIER_2_CHALLENGE": ("warn", "⏸️ Would be held for OTP"),
              "TIER_3_COOLING": ("bad", "🚫 Would be blocked"), "REJECTED": ("bad", "❌ Would be declined")}
TIER_KIND = {"TIER_1_PASS": ("ok", "CLEARED"), "TIER_2_CHALLENGE": ("warn", "OTP HOLD"),
             "TIER_3_COOLING": ("bad", "BLOCKED")}


def pill(status):
    k, label = STATUS_META.get(status, ("warn", status))
    return Raw(f'<span class="pill" style="background:var(--{k}-bg);border-color:var(--{k}-bd);color:var(--{k}-tx)">{esc(label)}</span>')


def donut(score, tier):
    kind, label = TIER_KIND.get(tier, ("bad", "N/A"))
    pct = max(0.0, min(100.0, round(score * 100, 1)))
    dash = round(pct * 2.83, 1)
    return H(f"""
    <div style="display:flex;align-items:center;justify-content:center;gap:34px;flex-wrap:wrap;padding:8px 0;">
      <div style="position:relative;width:200px;height:200px;">
        <svg viewBox="0 0 100 100" style="width:200px;height:200px;transform:rotate(-90deg);">
          <circle cx="50" cy="50" r="45" fill="none" style="stroke:var(--border)" stroke-width="10"/>
          <circle cx="50" cy="50" r="45" fill="none" style="stroke:var(--{kind}-bd)" stroke-width="10"
                  stroke-dasharray="283" stroke-dashoffset="{283 - dash}" stroke-linecap="round"/>
        </svg>
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;">
          <div style="font-size:2.3rem;font-weight:800;color:var(--{kind}-tx);line-height:1;">{pct}%</div>
          <div style="font-size:.9rem;font-weight:700;color:var(--muted);margin-top:4px;">composite risk</div>
        </div>
      </div>
      <div>
        <div class="tl">Verdict</div>
        <div style="font-size:2rem;font-weight:800;color:var(--{kind}-tx);">{label}</div>
        <div style="font-size:1.05rem;font-weight:600;color:var(--text);">Safe margin: {round(100 - pct, 1)}%</div>
      </div>
    </div>""")


def render_decision(t, simulated=False):
    tier = t["tier"]
    if simulated:
        kind, title = SIM_BANNER.get(tier, ("bad", "Result"))
    else:
        kind = STATUS_META.get(t["status"], ("warn", ""))[0]
        title = BANNER.get(t["status"], t["status"])
    notice(kind, title, esc(t["reason"]))
    rf = t.get("rf_risk")
    md(f'<div class="chips"><span class="chip">⚡ Engine latency: {t["latency_ms"]} ms (measured)</span>'
       f'<span class="chip">📊 Composite risk: {t["score"] * 100:.1f}%</span>'
       f'<span class="chip">🌲 Random Forest risk: {"model not loaded" if rf is None else f"{rf * 100:.1f}%"}</span></div>')
    if tier != "REJECTED":
        md(f'<div class="card"><div class="card-title">Live behavioural risk gauge</div>{donut(t["score"], tier)}</div>')
        tiles([("Account drain", f'{t["drain_ratio"] * 100:.1f}%', "info"),
               ("Spend multiplier", f'{t["amount_to_avg"]:.1f}x', "info"),
               ("Implied travel speed", f'{t["speed_kmh"]:,.0f} km/h', "info"),
               ("Random Forest risk", "n/a" if rf is None else f"{rf * 100:.1f}%", "warn")])
    with st.expander("🔍 Explainable audit checklist (every check that ran)", expanded=False):
        for i, (name, detail, state) in enumerate(t["log"], 1):
            k = "ok" if state == "OK" else "bad"
            md(f'<div class="step"><div><div class="sn">{i}. {esc(name)}</div><div class="sd">{esc(detail)}</div></div>'
               f'<span class="pill" style="background:var(--{k}-bg);border-color:var(--{k}-bd);color:var(--{k}-tx)">'
               f'{"✓ OK" if state == "OK" else "⚠ ALERT"}</span></div>')


# =============================================================================
# Cached resources and session state
# =============================================================================
@st.cache_resource
def boot():
    engine.init_db()
    return engine.load_model(os.path.dirname(os.path.abspath(__file__)) or ".")


MODEL, SCALER, MODEL_ERR = boot()

st.session_state.setdefault("nav", "Home")
st.session_state.setdefault("co_nonce", 0)
st.session_state.setdefault("ma_reset", 0)
if "dark_toggle" not in st.session_state:
    st.session_state["dark_toggle"] = st.query_params.get("theme") == "dark"
if "did" not in st.query_params:
    st.query_params["did"] = "dev-" + secrets.token_hex(3)
DEVICE_ID = st.query_params["did"]


def go(page):
    st.session_state["nav"] = page


# ----------------------------- sidebar ---------------------------------------
with st.sidebar:
    md('<div style="font-size:1.7rem;font-weight:800;color:var(--text);margin-bottom:6px;">🛡️ UPI Shield</div>')
    st.radio("Navigate", PAGES, key="nav", label_visibility="collapsed")
    dark = st.toggle("🌙 Dark mode", key="dark_toggle")
    THEME = "dark" if dark else "light"
    if st.query_params.get("theme") != THEME:
        st.query_params["theme"] = THEME
    st.markdown("---")
    if MODEL is None:
        notice("bad", "Model not loaded", esc(MODEL_ERR))
    else:
        md(f'<div class="muted" style="font-weight:700;">🌲 {esc(type(MODEL).__name__)} loaded</div>')
    md(f'<div class="muted" style="font-weight:600;line-height:1.9;">🕒 Time zone: IST<br>'
       f'📱 This device: <code>{esc(DEVICE_ID)}</code><br>⚡ Team: Spark Squad</div>')

st.markdown(theme_css(THEME), unsafe_allow_html=True)


# =============================================================================
# PAGE: HOME
# =============================================================================
def page_home():
    left, right = st.columns([1.6, 1])
    with left:
        md('<div class="hero">🛡️ UPI Shield</div><div class="hero-sub">Stop UPI fraud before the money leaves the account</div>'
           '<div class="hero-p">UPI Shield sits inline between the payment app and the bank debit. Every payment is checked '
           'against the payer\'s own history (device, location, velocity, beneficiary, spending habit) by transparent rules '
           'and a trained <strong>Random Forest</strong> model. The result is one of three actions: approve, hold for an OTP, '
           'or block.</div>')
        st.button("Get Started →", type="primary", on_click=go, args=("Fraud Detection",))
    with right:
        md("""<div style="display:flex;justify-content:center;padding-top:10px;">
        <svg width="260" height="290" viewBox="0 0 200 220" xmlns="http://www.w3.org/2000/svg">
        <path d="M100 12 L178 42 V104 C178 152 146 188 100 208 C54 188 22 152 22 104 V42 Z"
              style="fill:var(--info-bg);stroke:var(--accent)" stroke-width="6" stroke-linejoin="round"/>
        <path d="M66 108 L92 134 L138 82" fill="none" style="stroke:var(--ok-bd)" stroke-width="14"
              stroke-linecap="round" stroke-linejoin="round"/></svg></div>""")
    st.markdown("---")
    stats = engine.ledger_stats()
    md('<div class="page-h">What it does</div>')
    f1, f2, f3 = st.columns(3)
    with f1:
        lat = f"Measured engine latency on this ledger: {stats['avg_latency']:.1f} ms average." if stats else \
            "Latency is measured for every payment and shown on the Dashboard."
        md(f'<div class="feat-t">⚡ Inline, pre-debit</div><div class="feat-p">Decisions are made before settlement. A blocked payment never debits the account. {lat}</div>')
    with f2:
        md('<div class="feat-t">🌲 Model plus rules</div><div class="feat-p">A Random Forest scores behavioural features. Hard rules (scam keywords, impossible travel, liened beneficiaries) can override it, and every check is listed in the audit trail.</div>')
    with f3:
        md('<div class="feat-t">🧾 A real ledger</div><div class="feat-p">Balances, devices, payees, OTPs and liens are stored in a database, so history changes future decisions, exactly as in a live system.</div>')


# =============================================================================
# PAGE: DASHBOARD
# =============================================================================
@st.cache_data(show_spinner=False)
def read_csv_cached(path, mtime):
    return pd.read_csv(path)


def find_dataset():
    cands = [os.environ.get("UPI_DATASET", ""), "upi_fraud_dataset.csv", "dataset.csv", "transactions.csv"]
    for p in cands:
        if p and os.path.exists(p):
            return p
    return None


def page_dashboard():
    md('<div class="page-h">📊 Dashboard</div><div class="page-s">Live numbers from the ledger, the loaded model, and your training data.</div>')
    t_live, t_model, t_data, t_how = st.tabs(["Live operations", "Model", "Training data", "How it works"])

    with t_live:
        s = engine.ledger_stats()
        if not s:
            notice("info", "No payments processed yet", "Make a payment in <strong>Fraud Detection → Merchant Checkout</strong> and this page fills in automatically.")
        else:
            b = s["by_status"]
            tiles([("Payments processed", f'{s["total"]:,}', None),
                   ("Settled", f'{b.get("SUCCESS", 0):,}', "ok"),
                   ("Held / expired", f'{b.get("PENDING_OTP", 0) + b.get("EXPIRED", 0):,}', "warn"),
                   ("Blocked", f'{b.get("BLOCKED", 0):,}', "bad"),
                   ("Declined", f'{b.get("DECLINED", 0):,}', "bad")])
            tiles([("Value settled", f'₹{s["settled"]:,.0f}', "ok"),
                   ("Value stopped (blocked/expired)", f'₹{s["protected"]:,.0f}', "bad"),
                   ("Avg engine latency", f'{s["avg_latency"]:.1f} ms', "info"),
                   ("p95 engine latency", f'{s["p95_latency"]:.1f} ms', "info")])
            c1, c2 = st.columns(2)
            with c1:
                md(card("Decisions", bar_html(sorted(b.items(), key=lambda x: -x[1]), "--accent")))
            with c2:
                md(card("Most frequent risk signals", bar_html(sorted(s["flags"].items(), key=lambda x: -x[1])[:8], "--warn-bd")))
            md('<div class="card-title">Recent decisions</div>')
            rows = [{"time": t["ts"][5:19].replace("T", " "), "payer": t["sender"], "payee": t["receiver"],
                     "amount": f'₹{t["amount"]:,.0f}', "status": pill(t["status"]), "risk": f'{t["score"] * 100:.0f}%'}
                    for t in engine.list_transactions(10)]
            html_table(rows, [("time", "Time"), ("payer", "Payer"), ("payee", "Payee"), ("amount", "Amount"),
                              ("status", "Status"), ("risk", "Risk")])

    with t_model:
        info = engine.model_info(MODEL, SCALER)
        if not info:
            notice("bad", "Model not loaded", esc(MODEL_ERR) + "<br>Without a model the app scores with rules only and says so.")
        else:
            p = info["params"]
            tiles([("Algorithm", info["type"], None), ("Trees", p.get("n_estimators", "n/a"), "info"),
                   ("Max depth", p.get("max_depth", "n/a"), "info"), ("Input features", len(info["features"]), "info")])
            st.caption("Values above are read from the loaded model file, not typed in.")
            c1, c2 = st.columns(2)
            with c1:
                md(card("Model parameters", table_html([{"k": k, "v": str(v)} for k, v in p.items()], [("k", "Parameter"), ("v", "Value")])))
            with c2:
                imp_html = (bar_html(sorted(info["importances"].items(), key=lambda x: -x[1]), "--accent", "{:.3f}")
                            if info["importances"] else '<div class="muted">This model does not expose feature importances.</div>')
                md(card("Feature importance", imp_html))

    with t_data:
        up = st.file_uploader("Upload your training dataset (CSV)", type=["csv"], key="ds_up")
        df, src = None, None
        if up is not None:
            df, src = pd.read_csv(up), up.name
        else:
            path = find_dataset()
            if path:
                df, src = read_csv_cached(path, os.path.getmtime(path)), path
        if df is None:
            notice("info", "No dataset connected", "Upload the CSV you trained on, or place it next to <code>app.py</code> as "
                   "<code>upi_fraud_dataset.csv</code>. All numbers on this tab are computed from the file, never typed in.")
        else:
            a = engine.analyze_dataset(df)
            st.caption(f"Source: {src}")
            items = [("Rows", f'{a["rows"]:,}', None)]
            if "fraud" in a:
                items += [("Fraudulent", f'{a["fraud"]:,}', "bad"), ("Legitimate", f'{a["legit"]:,}', "ok"),
                          ("Fraud rate", f'{a["fraud_rate"] * 100:.3f}%', "warn")]
            else:
                st.warning("No label column found (looked for is_fraud, fraud, label, target, class).")
            tiles(items)
            c1, c2 = st.columns(2)
            with c1:
                md(card("Feature statistics", table_html(a["numeric"].astype(str).to_dict("records"),
                        [("feature", "Feature"), ("mean", "Mean"), ("min", "Min"), ("max", "Max")])))
            with c2:
                if "amount_buckets" in a:
                    md(card("Transaction amount distribution", bar_html(a["amount_buckets"], "--link")))
                if "amount_by_class" in a:
                    md(card("Mean amount by class", bar_html([(f"class {k}", v) for k, v in a["amount_by_class"].items()], "--bad-bd", "₹{:,.0f}")))

    with t_how:
        md("""<div class="card"><div class="card-title">The pipeline for every payment</div>
        <div class="feat-p">
        <strong>1. Context from the ledger.</strong> Time since the last settled payment, distance between the last and current city,
        attempts in the last 10 minutes, whether the payee was paid before, whether the device is trusted.<br><br>
        <strong>2. Ten explainable checks.</strong> Liquidity, beneficiary lien, scam keywords in the UPI ID, travel speed, balance drain,
        spending surge, device, time window, payee history, attempt velocity.<br><br>
        <strong>3. Random Forest.</strong> The behavioural features are scaled and scored by the trained model.<br><br>
        <strong>4. Composite score and policy.</strong> Hard signals force a block, combinations raise the score, and the thresholds you set
        in Settings decide approve, hold or block.<br><br>
        <strong>5. Action.</strong> Approved payments settle and move balances. Held payments wait for a one-time code with expiry and an
        attempt limit. Blocked payments never debit, and can be reported, liened and documented.</div></div>""")


# =============================================================================
# Transaction panel (result, OTP, remediation) used in checkout and ledger
# =============================================================================
def render_txn_panel(txn_id, scope):
    flash = st.session_state.pop(f"flash_{scope}", None)
    if flash:
        (st.success if flash[0] else st.error)(flash[1])
    t = engine.get_txn(txn_id)
    if not t:
        st.warning("Transaction not found.")
        return
    render_decision(t)

    if t["status"] == "PENDING_OTP":
        otp = engine.otp_state(txn_id)
        md('<div class="card"><div class="card-title">🔐 Step-up authentication</div>'
           '<div class="muted">A one-time code was generated and "sent" to the payer\'s registered phone. This build has no SMS provider, '
           'so the message appears in the phone inbox below. Codes are random, stored hashed, expire in 5 minutes and allow 3 attempts.</div></div>')
        for m in engine.latest_sms(t["sender"], 2):
            md(f'<div class="sms"><div class="tl">SMS · {esc(m["ts"][11:19])}</div>{esc(m["body"])}</div>')
        if otp:
            st.caption(f"Expires at {otp['expires'][11:19]} IST · {otp['attempts_left']} attempt(s) left · {otp['resends_left']} resend(s) left")
        c1, c2, c3 = st.columns([1.6, 1, 1])
        code = c1.text_input("Enter 4-digit OTP", max_chars=4, key=f"otp_{scope}_{txn_id}")
        c2.write("")
        c3.write("")
        if c2.button("🔓 Verify & release", type="primary", key=f"otpv_{scope}_{txn_id}"):
            st.session_state[f"flash_{scope}"] = engine.verify_otp(txn_id, code)
            st.rerun()
        if c3.button("↻ Resend OTP", key=f"otpr_{scope}_{txn_id}"):
            st.session_state[f"flash_{scope}"] = engine.resend_otp(txn_id)
            st.rerun()
    elif t["status"] == "SUCCESS":
        a = engine.get_account(t["sender"])
        md(f'<div class="card"><div class="card-title">🧾 Receipt</div><div class="codebox">UTR            : {esc(t["utr"])}\n'
           f'Transaction ID : {esc(t["id"])}\nPaid to        : {esc(t["receiver"])}\nAmount         : ₹{t["amount"]:,.2f}\n'
           f'Time           : {esc(t["ts"])}\nPayer balance  : ₹{a["balance"]:,.2f}</div></div>'.replace("\n", "&#10;"))

    with st.expander("🚨 Report, lien and dispute tools", expanded=t["status"] in ("BLOCKED", "PENDING_OTP")):
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**📞 Cyber Crime Helpline**")
            st.caption("Dial 1930 immediately for a fraud that already happened.")
            st.link_button("Open cybercrime.gov.in", "https://cybercrime.gov.in")
        with c2:
            st.markdown("**🔒 Beneficiary lien**")
            liens = {l["vpa"] for l in engine.list_liens()}
            if t["receiver"] in liens:
                st.caption(f"Active on {t['receiver']}. Later payments to it are blocked.")
                if st.button("Remove lien", key=f"unlien_{scope}_{txn_id}"):
                    engine.remove_lien(t["receiver"])
                    st.rerun()
            else:
                st.caption("Blocks every future payment to this beneficiary.")
                if st.button("Place lien", key=f"lien_{scope}_{txn_id}"):
                    engine.place_lien(t["receiver"], f"Reported from {t['id']}", t["id"])
                    st.rerun()
        with c3:
            st.markdown("**📄 Complaint dossier**")
            key = f"dossier_{txn_id}"
            if st.button("Generate dossier", key=f"dsp_{scope}_{txn_id}"):
                st.session_state[key] = engine.create_dispute(txn_id)
            if key in st.session_state:
                did, body = st.session_state[key]
                st.download_button("📥 Download (.txt)", body, file_name=f"{did}.txt", key=f"dl_{scope}_{txn_id}")


# =============================================================================
# TAB: MERCHANT CHECKOUT
# =============================================================================
def apply_scan(text, source):
    try:
        p = engine.parse_upi_link(text)
    except ValueError as e:
        st.session_state["co_scan_msg"] = ("bad", f"{source}: {e}")
        return
    st.session_state["co_prefill"] = p
    st.session_state["co_nonce"] += 1
    amt = f" for ₹{p['amount']:,.2f}" if p["amount"] else ""
    st.session_state["co_scan_msg"] = ("ok", f"{source}: read payee <strong>{esc(p['vpa'])}</strong>{amt}. Details are filled in below.")
    st.rerun()


def tab_checkout():
    users = engine.list_accounts("user")
    labels = {u["vpa"]: f'{u["name"]} · {u["vpa"]}' for u in users}
    payer = st.selectbox("Pay from account", list(labels), format_func=labels.get, key="co_payer")
    acct = engine.get_account(payer)
    avail = engine.available_balance(payer)
    devs = engine.list_devices(payer)
    trusted = engine.device_known(payer, DEVICE_ID)
    tiles([("Balance", f'₹{acct["balance"]:,.2f}', None), ("Available (after holds)", f'₹{avail:,.2f}', "ok"),
           ("Usual spend", f'₹{acct["avg_spend"]:,.0f}', "info"), ("Trusted devices", len(devs), "info")])
    if not devs:
        st.info("First use of this account: this browser will be enrolled as the trusted device on the first payment.")
    elif not trusted:
        notice("warn", "This browser is not a trusted device for this account",
               "Payments from here are flagged <strong>NEW_DEVICE</strong>. That is the account-takeover signal.")
        if st.button("Trust this device", key="co_trust"):
            engine.register_device(payer, DEVICE_ID)
            st.rerun()

    nonce = st.session_state["co_nonce"]
    pre = st.session_state.get("co_prefill", {})
    left, right = st.columns([1.2, 1])

    with left:
        st.markdown("#### 1 · Payment method")
        method = st.radio("Method", ["UPI ID", "Scan QR", "UPI link"], horizontal=True,
                          key="co_method", label_visibility="collapsed")

        if method == "Scan QR":
            up = st.file_uploader("Upload a photo or screenshot of a UPI QR", type=["png", "jpg", "jpeg", "webp"],
                                  key=f"co_qr_up_{nonce}")
            if st.checkbox("Use camera instead", key="co_use_cam"):
                cam = st.camera_input("Point the camera at a UPI QR", key=f"co_cam_{nonce}")
                up = up or cam
            if up is not None:
                data = up.getvalue()
                sig = hashlib.md5(data).hexdigest()
                if st.session_state.get("co_qr_sig") != sig:
                    st.session_state["co_qr_sig"] = sig
                    text = engine.decode_qr(data)
                    if text is None:
                        st.session_state["co_scan_msg"] = ("bad", "No QR code found in that image. Try a sharper, closer photo.")
                    else:
                        apply_scan(text, "QR scan")
            with st.expander("Create a payee QR code (what a merchant or a scammer would show you)"):
                g_vpa = st.text_input("Payee UPI ID", value="chai_point@upi", key="gen_vpa")
                g_name = st.text_input("Display name", value="Chai Point", key="gen_name")
                g_amt = st.number_input("Amount (₹, 0 = payer enters it)", min_value=0.0, value=0.0, step=50.0, key="gen_amt")
                if st.button("Generate QR", key="gen_btn"):
                    try:
                        link = engine.build_upi_link(g_vpa, g_name, g_amt or None)
                        st.session_state["gen_qr"] = (link, engine.make_qr_png(link))
                    except ImportError:
                        st.error("The 'qrcode' package is missing. Run: pip install qrcode[pil]")
                if "gen_qr" in st.session_state:
                    link, png = st.session_state["gen_qr"]
                    st.image(png, width=220)
                    st.code(link, language=None)
                    d1, d2 = st.columns(2)
                    d1.download_button("📥 Download PNG", png, file_name="upi_qr.png", key="gen_dl")
                    if d2.button("📷 Scan this QR", key="gen_scan"):
                        text = engine.decode_qr(png)
                        apply_scan(text or "", "QR scan")
        elif method == "UPI link":
            link_in = st.text_input("Paste a upi://pay link", placeholder="upi://pay?pa=merchant@upi&pn=Shop&am=250", key=f"co_link_{nonce}")
            if st.button("Read link", key="co_link_btn"):
                apply_scan(link_in, "UPI link")

        msg = st.session_state.get("co_scan_msg")
        if msg:
            notice("ok" if msg[0] == "ok" else "bad", "QR / link result", msg[1] if msg[0] == "ok" else esc(msg[1]))

        st.markdown("#### 2 · Payee and amount")
        payee = st.text_input("Payee UPI ID", value=pre.get("vpa", ""), placeholder="merchant@upi", key=f"co_vpa_{nonce}")
        amount = st.number_input("Amount (₹)", min_value=0.0, value=float(pre.get("amount") or 0.0), step=100.0, key=f"co_amt_{nonce}")
        note = st.text_input("Note (optional)", value=pre.get("note", ""), key=f"co_note_{nonce}")
        pv = payee.strip().lower()
        known = engine.get_account(pv) if pv else None
        if known and known["kind"] == "merchant":
            st.success(f"Registered merchant: {known['name']}")
        elif pv:
            if not engine.VPA_RE.match(pv):
                st.error("That is not a valid UPI ID (expected name@bank).")
            else:
                st.caption("Unregistered payee. The shield treats this as an unverified beneficiary.")

    with right:
        st.markdown("#### 3 · Payer context")
        cities = list(engine.CITIES)
        city = st.selectbox("Your current city", cities, index=cities.index(acct["home_city"]),
                            key=f"co_city_{payer}")
        st.caption("Distance since your last settled payment and the time elapsed give the travel speed. Try a far city right after a payment.")
        active_call = st.checkbox("📞 I am on a call with someone I do not know", key="co_call")
        ext_link = st.checkbox("🔗 I opened this payment from an SMS / WhatsApp link", key="co_link_flag")
        override = True
        if active_call or ext_link:
            notice("bad", "Scam warning",
                   "Police, banks and government offices never ask for UPI payments over a call or a link. Stop and verify through an official number.")
            override = st.checkbox("I have verified the payee myself and want to continue", key="co_override")

    can_pay = amount > 0 and bool(pv) and engine.VPA_RE.match(pv) is not None and override
    b1, b2 = st.columns([2, 1])
    if b1.button(f"🚀 Pay ₹{amount:,.2f}", type="primary", disabled=not can_pay, key="co_pay"):
        txn = engine.process_payment(MODEL, SCALER, sender=payer, receiver=pv, amount=amount,
                                     channel=method, city=city, device_id=DEVICE_ID,
                                     active_call=active_call, ext_link=ext_link, note=note)
        st.session_state["co_active"] = txn["id"]
        st.session_state.pop("co_prefill", None)
        st.session_state.pop("co_scan_msg", None)
        st.session_state["co_nonce"] += 1
        st.rerun()
    if b2.button("➕ New payment", key="co_new"):
        for k in ("co_active", "co_prefill", "co_scan_msg", "co_qr_sig"):
            st.session_state.pop(k, None)
        st.session_state["co_nonce"] += 1
        st.rerun()

    if st.session_state.get("co_active"):
        st.markdown("---")
        render_txn_panel(st.session_state["co_active"], "co")


# =============================================================================
# TAB: MANUAL ANALYSIS (what-if, does not move money)
# =============================================================================
def tab_manual():
    md('<div class="muted" style="margin-bottom:10px;">Stress-test the engine with any combination of inputs. '
       '<strong>This is analysis only</strong>: it writes nothing to the ledger and moves no money.</div>')
    reset = st.session_state["ma_reset"]
    preset = st.selectbox("Start from a persona", list(engine.PROFESSIONS), key="ma_preset")
    base = engine.PROFESSIONS[preset]
    sfx = f"{preset}_{reset}"
    c1, c2 = st.columns(2)
    with c1:
        amount = st.number_input("Transaction amount (₹)", min_value=0.0, value=0.0, step=500.0, key=f"ma_amt_{sfx}")
        balance = st.number_input("Available balance (₹)", min_value=0.0, value=float(base["balance"]), step=1000.0, key=f"ma_bal_{sfx}")
        avg = st.number_input("Usual spend baseline (₹)", min_value=0.0, value=float(base["avg_spend"]), step=100.0, key=f"ma_avg_{sfx}")
        vpa = st.text_input("Beneficiary UPI ID", value="", placeholder="merchant@upi", key=f"ma_vpa_{sfx}")
        new_payee = st.selectbox("Beneficiary", ["Known payee", "New payee"], key=f"ma_payee_{sfx}") == "New payee"
    with c2:
        dist = st.number_input("Distance from last payment (km)", min_value=0.0, value=0.0, step=5.0, key=f"ma_dist_{sfx}")
        g1, g2 = st.columns(2)
        gval = g1.number_input("Time since last payment", min_value=0.0, value=60.0, step=1.0, key=f"ma_gv_{sfx}")
        gunit = g2.selectbox("Unit", ["Minutes", "Seconds", "Hours"], key=f"ma_gu_{sfx}")
        txc = st.number_input("Attempts in the last 10 minutes", min_value=0, max_value=50, value=1, key=f"ma_tx_{sfx}")
        new_dev = st.selectbox("Device", ["Trusted device", "Unrecognised device"], key=f"ma_dev_{sfx}") == "Unrecognised device"
        t_in = st.time_input("Transaction time", value=dtime(12, 0), key=f"ma_time_{sfx}")
    gap = gval * {"Minutes": 60, "Seconds": 1, "Hours": 3600}[gunit]
    r1, r2 = st.columns([2, 1])
    if r1.button("⚡ Run analysis", type="primary", key="ma_run"):
        res = engine.investigate(MODEL, SCALER, engine.get_policy(), amount=amount, balance=balance, avg_spend=avg,
                                 hour_24=t_in.hour, tx_count=txc, is_new_device=new_dev, is_new_payee=new_payee,
                                 dist_km=dist, gap_sec=gap, receiver_vpa=vpa.strip().lower() or "unknown@upi")
        st.session_state["ma_res"] = res
    if r2.button("🔄 Reset inputs", key="ma_clear"):
        st.session_state["ma_reset"] += 1
        st.session_state.pop("ma_res", None)
        st.rerun()
    if "ma_res" in st.session_state:
        st.markdown("---")
        render_decision(st.session_state["ma_res"], simulated=True)


# =============================================================================
# TAB: LEDGER
# =============================================================================
def tab_ledger():
    all_t = engine.list_transactions(500)
    if not all_t:
        notice("info", "The ledger is empty", "Payments made in Merchant Checkout are recorded here with their full audit trail.")
    else:
        wanted = st.multiselect("Filter by status", list(STATUS_META), default=list(STATUS_META), key="lg_filter")
        rows_t = [t for t in all_t if t["status"] in wanted]
        rows = [{"time": t["ts"][5:19].replace("T", " "), "id": t["id"], "payer": t["sender"], "payee": t["receiver"],
                 "amount": f'₹{t["amount"]:,.2f}', "channel": t["channel"], "status": pill(t["status"]),
                 "risk": f'{t["score"] * 100:.0f}%', "signals": ", ".join(t["flags"]) or "none"} for t in rows_t]
        html_table(rows, [("time", "Time"), ("id", "ID"), ("payer", "Payer"), ("payee", "Payee"), ("amount", "Amount"),
                          ("channel", "Channel"), ("status", "Status"), ("risk", "Risk"), ("signals", "Signals")])
        csv = pd.DataFrame([{k: (", ".join(v) if k == "flags" else v) for k, v in t.items()
                             if k in ("ts", "id", "sender", "receiver", "amount", "channel", "status", "tier",
                                      "score", "rf_risk", "flags", "latency_ms", "city", "utr", "reason")}
                            for t in rows_t]).to_csv(index=False)
        st.download_button("📥 Export ledger (CSV)", csv, file_name="upi_shield_ledger.csv", key="lg_csv")
        pick = st.selectbox("Inspect a transaction", [t["id"] for t in rows_t], key="lg_pick") if rows_t else None
        if pick:
            render_txn_panel(pick, "lg")

    st.markdown("---")
    st.markdown("#### 🔒 Active beneficiary liens")
    liens = engine.list_liens()
    if not liens:
        st.caption("None. Place one from any transaction's report tools.")
    for l in liens:
        c1, c2 = st.columns([4, 1])
        c1.markdown(f"`{l['vpa']}` · {l['reason']} · {l['ts'][:19].replace('T', ' ')}")
        if c2.button("Remove", key=f"lg_unlien_{l['vpa']}"):
            engine.remove_lien(l["vpa"])
            st.rerun()


# =============================================================================
# PAGE: FRAUD DETECTION
# =============================================================================
def page_detection():
    md('<div class="page-h">🛡️ Fraud Detection</div><div class="page-s">Merchant checkout → inline shield → bank debit, backed by a persistent ledger.</div>')
    if MODEL is None:
        notice("bad", "Random Forest model not loaded", esc(MODEL_ERR) +
               "<br>The app is running on rules only. Risk scores are labelled accordingly.")
    t1, t2, t3 = st.tabs(["🛒 Merchant checkout", "🧪 Manual analysis", "🧾 Ledger & remediation"])
    with t1:
        tab_checkout()
    with t2:
        tab_manual()
    with t3:
        tab_ledger()


# =============================================================================
# PAGE: SETTINGS
# =============================================================================
def page_settings():
    md('<div class="page-h">⚙️ Settings</div><div class="page-s">Policy changes apply to the very next payment.</div>')
    pol = engine.get_policy()
    md('<div class="card-title">Decision policy</div>')
    c1, c2 = st.columns(2)
    with c1:
        review = st.slider("Hold for OTP at composite risk ≥", 0.05, 0.95, float(pol["review_threshold"]), 0.01, key="pol_review")
        block = st.slider("Block at composite risk ≥", 0.50, 1.00, float(pol["block_threshold"]), 0.01, key="pol_block")
        soft = st.checkbox("Hold even when only a soft signal fires (off-hours or new payee alone)",
                           value=bool(pol["soft_flags_alone_hold"]), key="pol_soft")
    with c2:
        drain = st.slider("High-drain limit (share of balance)", 0.10, 1.00, float(pol["drain_limit"]), 0.05, key="pol_drain")
        spike = st.slider("Spending-spike limit (x usual spend)", 1.0, 20.0, float(pol["spike_limit"]), 0.5, key="pol_spike")
        speed = st.slider("Impossible-speed limit (km/h)", 50.0, 1000.0, float(pol["speed_limit_kmh"]), 10.0, key="pol_speed")
    if review >= block:
        st.error("The OTP threshold must be lower than the block threshold.")
    elif st.button("💾 Save policy", type="primary", key="pol_save"):
        engine.set_policy({"review_threshold": review, "block_threshold": block, "drain_limit": drain,
                           "spike_limit": spike, "speed_limit_kmh": speed, "soft_flags_alone_hold": soft})
        st.success("Policy saved.")

    st.markdown("---")
    md('<div class="card-title">Trusted devices</div>')
    devs = engine.list_devices()
    if not devs:
        st.caption("No devices enrolled yet. The first payment from an account enrols the browser used.")
    for d in devs:
        c1, c2 = st.columns([4, 1])
        c1.markdown(f"`{d['vpa']}` · device `{d['device_id']}` {'(this browser)' if d['device_id'] == DEVICE_ID else ''}")
        if c2.button("Remove", key=f"dev_rm_{d['vpa']}_{d['device_id']}"):
            engine.remove_device(d["vpa"], d["device_id"])
            st.rerun()

    st.markdown("---")
    md('<div class="card-title">Data</div>')
    st.caption(f"Database file: {os.path.abspath(engine.DB_PATH)}")
    st.caption("Resetting deletes every transaction, OTP, lien, dispute and device, and restores the starting balances.")
    if st.checkbox("I understand this cannot be undone", key="rst_ok") and st.button("🗑️ Reset all demo data", key="rst_btn"):
        engine.reset_db()
        for k in ("co_active", "co_prefill", "co_scan_msg", "ma_res"):
            st.session_state.pop(k, None)
        st.success("Everything was reset.")
        st.rerun()


# =============================================================================
# ROUTER
# =============================================================================
{"Home": page_home, "Dashboard": page_dashboard, "Fraud Detection": page_detection,
 "Settings": page_settings}[st.session_state["nav"]]()
