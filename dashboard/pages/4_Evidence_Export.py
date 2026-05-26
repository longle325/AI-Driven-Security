from __future__ import annotations

import streamlit as st

from src.config import EXPORT_DIR
from src.evidence_exporter import export_evidence


st.title("Evidence Export")

if st.button("Generate Evidence Bundle"):
    result = export_evidence()
    st.success(f"Evidence exported to {result['export_dir']}")

st.subheader("Export Files")
if not EXPORT_DIR.exists():
    st.info("No export directory yet.")
else:
    for path in sorted(EXPORT_DIR.iterdir()):
        if path.is_file():
            st.write(f"- `{path.name}`")
            if path.suffix in {".csv", ".json", ".jsonl", ".md", ".txt"}:
                st.download_button(
                    label=f"Download {path.name}",
                    data=path.read_bytes(),
                    file_name=path.name,
                    key=str(path),
                )

st.subheader("Demo Checklist")
st.checkbox("Docker lab starts locally")
st.checkbox("Normal events generated")
st.checkbox("Suspicious scenario generated")
st.checkbox("Rule-based and ML detection compared")
st.checkbox("Evidence exported")
st.checkbox("Ethics/legal scope explained")
