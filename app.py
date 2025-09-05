# app.py — DevGuard Streamlit Frontend (dynamic, not static)
# Run on Replit or locally: `pip install -r requirements.txt` then `streamlit run app.py`

import json
import os
import io
import requests
import streamlit as st

st.set_page_config(page_title="DevGuard — Scan your no‑code export", page_icon="🛡️", layout="centered")

# ---- Config ----
DEFAULT_BACKEND = os.environ.get("BACKEND_URL", st.secrets.get("BACKEND_URL", "https://YOUR-BACKEND-REPL-URL.replit.app"))
if "BACKEND_URL" not in st.session_state:
    st.session_state["BACKEND_URL"] = DEFAULT_BACKEND

# ---- Sidebar ----
st.sidebar.title("DevGuard Settings")
st.sidebar.text_input("Backend URL", key="BACKEND_URL", help="Your FastAPI base URL (e.g., https://<name>.replit.app)")
st.sidebar.markdown("---")
st.sidebar.markdown("**Ethics**: Scan only apps you own. No data stored. Rate‑limited.")

# ---- Title ----
st.title("DevGuard — Scan your no‑code export")
st.caption("Upload an export (JSON/YAML) or paste an OpenAPI spec. Get a Security Score with actionable fixes.")

# ---- Tabs ----
scan_tab, results_tab, about_tab = st.tabs(["🔍 Scan", "📊 Results", "📜 About / Ethics"])

# Session containers
if "scan" not in st.session_state:
    st.session_state.scan = None

# ---------- Tab: Scan ----------
with scan_tab:
    c1, c2 = st.columns([1, 1])
    with c1:
        up = st.file_uploader("Upload JSON/YAML export", type=["json","yaml","yml"], accept_multiple_files=False)
        st.button("Quick Demo", key="demo_btn")
    with c2:
        openapi_text = st.text_area("…or paste OpenAPI JSON", height=180, placeholder="{\n  \"openapi\": \"3.0.0\", ...\n}")

    run = st.button("Run Scan", use_container_width=True, type="primary")

    if st.session_state.get("demo_btn") and not up and not openapi_text.strip():
        # Preload a tiny demo specimen in the textarea
        demo = {
            "endpoints": [
                {"path": "/users", "auth": "none", "returns": ["email", "name"]},
                {"path": "/search", "auth": "none", "cors": "*"},
                {"path": "/bundle.js", "leaks": ["X-API-Key"]},
            ]
        }
        st.session_state.setdefault("openapi_demo", json.dumps(demo, indent=2))
        st.rerun()

    if "openapi_demo" in st.session_state and not openapi_text.strip():
        st.info("Loaded demo specimen. You can edit it or click Run Scan.")
        st.code(st.session_state.openapi_demo, language="json")

    if run:
        backend = st.session_state["BACKEND_URL"].rstrip("/")
        payload: dict = {"demo": False}
        if up is not None:
            try:
                text = up.read().decode("utf-8", errors="ignore")
            except Exception:
                text = up.getvalue().decode("utf-8", errors="ignore")
            payload["file"] = text
        elif openapi_text.strip():
            payload["openapi"] = openapi_text
        elif "openapi_demo" in st.session_state:
            payload["demo"] = True
        else:
            payload["demo"] = True

        with st.status("Scanning… Parsing → Applying rules → Scoring", expanded=False):
            try:
                r = requests.post(f"{backend}/scan", json=payload, timeout=90)
                r.raise_for_status()
                st.session_state.scan = r.json()
            except Exception as e:
                st.error(f"Scan failed: {e}")
            else:
                st.success("Scan complete")
        

# ---------- Helpers ----------
SEVERITY_ORDER = {"high": 3, "med": 2, "low": 1}

def score_label(score: int) -> str:
    if score >= 80: return "Excellent"
    if score >= 60: return "Good"
    if score >= 40: return "Fair"
    return "Poor"

# ---------- Tab: Results ----------
with results_tab:
    scan = st.session_state.scan
    if not scan:
        st.info("Run a scan to see results.")
    else:
        score = int(scan.get("score", 0))
        st.subheader("Security Score")
        st.metric("Score", f"{score}/100", help=score_label(score))
        st.progress(min(max(score, 0), 100) / 100)

        # Filter bar
        st.markdown("### Findings")
        severities = ["all", "high", "med", "low"]
        chosen = st.segmented_control("Filter by severity", severities, selection_mode="single", default="all", key="sev")

        items = scan.get("findings", [])
        if chosen != "all":
            items = [f for f in items if f.get("severity") == chosen]
        # Sort by severity
        items.sort(key=lambda f: SEVERITY_ORDER.get(f.get("severity","low"), 0), reverse=True)

        if not items:
            st.info("No findings for this filter.")
        else:
            for f in items:
                with st.expander(f"{f.get('severity','').upper()} — {f.get('title','')}", expanded=False):
                    details = f.get("details")
                    if details: st.write(details)
                    ev = f.get("evidence")
                    if ev is not None:
                        try:
                            st.code(json.dumps(ev, indent=2), language="json")
                        except Exception:
                            st.code(str(ev))
                    if st.button(f"Fix via Wrapper — {f.get('id','')}", key=f"apply_{f.get('id','')}"):
                        try:
                            rr = requests.post(f"{BACKEND_URL}/apply", json={"ids":[f.get("id")]}, timeout=60)
                            rr.raise_for_status()
                            st.session_state.scan = rr.json()
                            st.success("Fix applied and re-scanned.")
                            # st.switch_page("app.py") <-- REMOVE
                            st.experimental_rerun()    # optional
                        except Exception as e:
                            st.error(f"Apply failed: {e}")


        c1, c2 = st.columns([1,1])
        with c1:
            backend = st.session_state["BACKEND_URL"].rstrip("/")
            if st.button("Export PDF Report", use_container_width=True):
                try:
                    pdf = requests.get(f"{backend}/report.pdf", timeout=60)
                    pdf.raise_for_status()
                    st.download_button("Download report.pdf", data=pdf.content, file_name="devguard-report.pdf", mime="application/pdf")
                except Exception as e:
                    st.error(f"Could not fetch PDF: {e}")
        with c2:
            if st.button("Scan another app", use_container_width=True):
                st.session_state.scan = None
                st.experimental_rerun()

# ---------- Tab: About ----------
with about_tab:
    st.markdown(
        """
        **DevGuard** scans no‑code/low‑code app exports using platform‑aware rulepacks and suggests fixes.
        
        - We only scan assets you provide in this session; no persistent storage.
        - Use on apps you own. Be considerate: rate‑limited probing.
        - Wrapper auto‑fix simulates guardrails (rate limits, CORS, headers) for demo purposes.
        
        Built for hackathon judging: visible score, three concrete findings, and re‑scan improvement.
        """
    )
