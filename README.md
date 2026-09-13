# SafeWeights

**Static AI model intake scanner for Cybersecurity teams.**  
Pull from Hugging Face → scan without loading → plain-language Markdown report.

[![Python 3.14](https://img.shields.io/badge/python-3.14-22D3EE?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-0B1220?style=flat-square)](#license)

**Live site:** [Project Pages](https://Elpi97.github.io/SafeWeights/) *(enabled after first push)*

## What it does

SafeWeights helps security analysts review Hugging Face models **before** they reach Lambda / production:

1. Sign in with Hugging Face (device / browser link — same as `hf auth login`)
2. Pull a model ID into a chosen folder
3. Statically scan weights (pickle/PyTorch, safetensors, GGUF, ONNX, H5)
4. Generate a **non-technical** Markdown report (PASS / FAIL)

It does **not** execute model code during the scan.

## Quick start (Windows VE)

```powershell
cd SafeWeights
python -m pip install -r requirements.txt
python main.py
```

CLI:

```powershell
python -m safewights.cli -p "C:\path\to\model" --model-id org/name -o report.md
```

## Formats

| Format | Extensions | Check style |
|--------|------------|-------------|
| Pickle / PyTorch | `.pkl` `.pt` `.pth` `.bin` … | Opcode / import static analysis |
| SafeTensors | `.safetensors` | Header + offset validation |
| GGUF | `.gguf` | Magic / version / counts |
| ONNX | `.onnx` | Structure + suspicious markers |
| Keras H5 | `.h5` `.keras` | HDF5 magic + attribute scan |

## Project layout

```
safewights/          # app package
  gui/               # cyber-themed CustomTkinter UI
  scanner/           # format scanners
docs/                # GitHub Pages site
tests/smoke_test.py
main.py
```

## License

MIT — see repository license file once published.
