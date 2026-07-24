#!/usr/bin/env python3
"""QA montage helper — renders the report PDF to ONE stitched PNG."""
from __future__ import annotations

import math
import os
import sys

from pdf2image import convert_from_path
from PIL import Image

OUT = os.environ.get("ADCS_AUDIT_OUTPUT", "/mnt/workspace/output")
WK = os.environ.get("ADCS_AUDIT_WORKING", "/mnt/workspace/working")

pdf = sys.argv[1] if len(sys.argv) > 1 else os.path.join(OUT, "ADCS_ESC_Audit_Report.pdf")
out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(WK, "qa_montage.png")
os.makedirs(os.path.dirname(out), exist_ok=True)

pages = convert_from_path(pdf, dpi=70)
cols = 3
rows = math.ceil(len(pages) / cols)
w = max(p.width for p in pages)
h = max(p.height for p in pages)
pad = 10
sheet = Image.new("RGB", (cols * w + (cols + 1) * pad, rows * h + (rows + 1) * pad), "#d0d6de")
for i, p in enumerate(pages):
    r, c = divmod(i, cols)
    sheet.paste(p, (pad + c * (w + pad), pad + r * (h + pad)))
maxw = 1700
if sheet.width > maxw:
    sheet = sheet.resize((maxw, int(sheet.height * maxw / sheet.width)))
sheet.save(out)
print(f"QA montage: {len(pages)} pages -> {out}  ({sheet.width}x{sheet.height})")
