# UEBA/SIEM Overleaf Report

This folder is ready to upload to Overleaf.

## Files

- `main.tex`: main LaTeX report.
- `figures/*.pdf`: generated plots used by the report.
- `scripts/generate_figures.py`: optional local script to regenerate figures from the datasets.

## Upload to Overleaf

1. Zip the contents of this folder, or use the generated `overleaf_report.zip` in the project root.
2. In Overleaf, create a new project from upload.
3. Upload the zip.
4. Compile `main.tex` with pdfLaTeX.

## Regenerate figures locally

From the project root:

```bash
.venv/bin/python overleaf_report/scripts/generate_figures.py
```

The script reads `dataset1/` and reuses `ueba_siem.py`, so the plots stay consistent with the implemented rules.
