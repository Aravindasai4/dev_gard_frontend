import json
import os
import requests
import streamlit as st

st.set_page_config(page_title="DevGuard — Scan your no‑code export", page_icon="🛡️", layout="centered")

# =========================
# Backend URL
# =========================
# Hardcode your live backend URL here; you can override it from the sidebar if needed.
DEFAULT_BACKEND_URL = "https://29397997-ac2a-4ac3-85e7-e303b2bf7132-00-261rsf50uxbvp.janeway.replit.dev"
BACKEND_URL = os.environ.get("BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/")

# State
if "scan" not in st.session_state:
    st.session_state.scan = None
if "backend" not in st.session_state:
    st.session_state.backend = BACKEND_URL

# Sidebar controls
st.sidebar.title("DevGuard Settings")
st.sidebar.text_input(
    "Backend URL",
    key="backend",
    help="Your FastAPI URL (e.g., https://<name>.replit.app)",
)
st.sidebar.caption("**Ethics:** Scan only apps you own. No data stored. Rate‑limited.")

# Title
st.title("DevGuard — Scan your no‑code export")
st.caption("Upload an export (JSON/YAML) or paste an OpenAPI spec. Get a Security Score with actionable fixes.")

# Tabs
scan_tab, results_tab, about_tab = st.tabs(["🔍 Scan", "📊 Results", "📜 About / Ethics"])

# --------------------------
# Helpers
# --------------------------

def post_json(endpoint: str, payload: dict, timeout: int = 45):
    url = f"{st.session_state.backend.rstrip('/')}{endpoint}"
    r = requests.post(url, json=payload, timeout=timeout)
    return r

# --------------------------
# Tab: Scan
# --------------------------
with scan_tab:
    left, right = st.columns([1,1])
    with left:
        up = st.file_uploader("Upload JSON/YAML export", type=["json","yaml","yml"], accept_multiple_files=False)
        st.write("")
        demo_clicked = st.button("Quick Demo")
    with right:
        openapi_text = st.text_area("…or paste OpenAPI JSON (optional)", height=180, placeholder='{"endpoints": [{"path": "/users", "auth": "none"}] }')
        url_to_scan = st.text_input("…or scan a live URL (optional)", placeholder="https://example.com")

    run = st.button("Run Scan", type="primary", use_container_width=True)

    if demo_clicked and not up and not openapi_text.strip() and not url_to_scan.strip():
        # preload a specimen for judges
        specimen = {
            "endpoints": [
                {"path": "/users", "auth": "none", "returns": ["email", "name"]},
                {"path": "/search", "auth": "none", "cors": "*"},
                {"path": "/bundle.js", "leaks": ["X-API-Key"]},
            ]
        }
        st.session_state.setdefault("openapi_demo", json.dumps(specimen, indent=2))
        st.info("Loaded demo specimen. Click Run Scan.")

    if "openapi_demo" in st.session_state and not openapi_text.strip():
        st.code(st.session_state.openapi_demo, language="json")

    if run:
        # Decide payload for backend /scan
        payload = {}
        # Highest priority: explicit URL (backend supports this)
        if url_to_scan.strip():
            payload = {"url": url_to_scan.strip()}
        # If no URL, fall back to demo (since current backend doesn't parse openapi/file)
        else:
            payload = {"demo": True}

        # Show a status line
        with st.status("Scanning… Parsing → Applying rules → Scoring", expanded=False):
            try:
                r = post_json("/scan", payload, timeout=60)
                # Debug surface to diagnose issues quickly
                st.write("DEBUG status:", r.status_code)
                st.write("DEBUG body:", r.text[:400])
                r.raise_for_status()
                st.session_state.scan = r.json()
                st.success("Scan complete")
            except Exception as e:
                st.error(f"Scan failed: {e}")

# --------------------------
# Tab: Results
# --------------------------
with results_tab:
    data = st.session_state.scan
    if not data:
        st.info("Run a scan to see results.")
    else:
        score = int(data.get("score", 0))
        st.subheader(f"Security Score: {score}/100")
        st.progress(min(max(score, 0), 100) / 100)

        findings = data.get("findings", [])
        if not findings:
            st.success("No active findings. 🎉")
        for i, f in enumerate(findings):
            fid = f.get("id") or f"auto_{i}"
            sev = (f.get("severity") or "").upper()
            title = f.get("title") or f"Finding {i+1}"

            with st.expander(f"{sev} — {title}", expanded=False, key=f"exp_{i}"):
                if f.get("details"):
                    st.write(f["details"])
                ev = f.get("evidence")
                if ev is not None:
                    try:
                        st.code(json.dumps(ev, indent=2), language="json")
                    except Exception:
                        st.code(str(ev))
                if st.button(f"Fix via Wrapper — {fid}", key=f"fix_{i}_{fid}"):
                    try:
                        rr = post_json("/apply", {"ids": [fid]}, timeout=45)
                        st.write("DEBUG apply status:", rr.status_code)
                        st.write("DEBUG apply body:", rr.text[:400])
                        rr.raise_for_status()
                        st.session_state.scan = rr.json()
                        st.success("Fix applied. Re-scanned.")
                        st.experimental_rerun()
                    except Exception as e:
                        st.error(f"Could not apply fix: {e}")

        # Export PDF
        if st.button("Export PDF Report", key="btn_pdf"):
            try:
                pdf_url = f"{st.session_state.backend.rstrip('/')}/report.pdf"
                pdf = requests.get(pdf_url, timeout=60)
                st.write("DEBUG pdf status:", pdf.status_code)
                pdf.raise_for_status()
                st.download_button("Download report.pdf", data=pdf.content, file_name="devguard-report.pdf", mime="application/pdf", key="dl_pdf")
            except Exception as e:
                st.error(f"Could not fetch PDF: {e}")

# --------------------------
# Tab: About / Ethics
# --------------------------
with about_tab:
    st.markdown(
        """
        **DevGuard** scans no‑code/low‑code app exports using platform‑aware rulepacks and suggests fixes.\
        For this demo, the scanner runs a minimal set of checks and the wrapper 'apply' simulates guardrails.

        **Notes**
        - Owned apps only. No persistent storage.\
        - The demo defaults to a sample scan if no URL is provided.\
        - Endpoints: `/scan`, `/apply`, `/report.pdf`, plus `/docs`.
        """
    )

st.caption(f"Backend: {st.session_state.backend}")
