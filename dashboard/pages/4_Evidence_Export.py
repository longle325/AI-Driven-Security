from __future__ import annotations

import streamlit as st

from dashboard.common import inject_console_theme
from src.config import EXPORT_DIR
from src.evidence_exporter import export_evidence


inject_console_theme()
st.title("Evidence Export")

if st.button("Generate Evidence Bundle", type="primary"):
    result = export_evidence()
    st.success(f"Evidence exported to {result['export_dir']}")

st.subheader("Export Manifest")
if not EXPORT_DIR.exists():
    st.info("No export directory yet.")
else:
    manifest = []
    for path in sorted(EXPORT_DIR.iterdir()):
        if path.is_file():
            manifest.append({"file": path.name, "size_kb": round(path.stat().st_size / 1024, 2), "type": path.suffix or "artifact"})
    st.dataframe(manifest, use_container_width=True, hide_index=True)
    for path in sorted(EXPORT_DIR.iterdir()):
        if path.is_file() and path.suffix in {".csv", ".json", ".jsonl", ".md", ".txt"}:
                st.download_button(
                    label=f"Download {path.name}",
                    data=path.read_bytes(),
                    file_name=path.name,
                    key=str(path),
                )

st.subheader("Demo Checklist")
left, right = st.columns(2)
left.checkbox("Docker services healthy")
left.checkbox("Normal baseline present")
left.checkbox("Suspicious scenarios generated")
right.checkbox("Rule and ML results compared")
right.checkbox("Evidence bundle exported")
right.checkbox("Ethics boundary stated")
