<p align="center">
  <img src="docs/assets/logo.png" alt="SafeWeights logo" width="160" />
</p>

<h1 align="center">SafeWeights</h1>

<p align="center">
  <strong>Static AI model intake scanner for Cybersecurity teams.</strong><br/>
  Pull from Hugging Face → scan without loading → plain-language Markdown report.
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.14-22D3EE?style=flat-square&logo=python&logoColor=white" alt="Python 3.14" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-0B1220?style=flat-square" alt="License" /></a>
  <a href="https://github.com/Elpi97/SafeWeights/releases/tag/v1.2.0"><img src="https://img.shields.io/badge/release-v1.2.0-22D3EE?style=flat-square" alt="Release" /></a>
</p>

**Live site:** [Project Pages](https://elpi97.github.io/SafeWeights/)  
**Release:** [v1.2.0](https://github.com/Elpi97/SafeWeights/releases/tag/v1.2.0)

## What it does

SafeWeights helps security analysts review Hugging Face models **before** they reach Lambda / production:

1. Sign in with Hugging Face (device / browser link — same as `hf auth login`)
2. Pull a model ID into a chosen folder
3. Statically scan weights (pickle/PyTorch, safetensors, GGUF, ONNX, H5)
4. Generate a **non-technical** Markdown report (PASS / FAIL)

It does **not** execute model code during the scan.

## Install from GitHub Release

```powershell
pip install https://github.com/Elpi97/SafeWeights/releases/download/v1.2.0/safewights-1.2.0-py3-none-any.whl
safewights --gui
```

## Container package (GHCR)

After the release workflow finishes:

```powershell
docker pull ghcr.io/elpi97/safewights:1.2.0
docker run --rm ghcr.io/elpi97/safewights:1.2.0 --help
```

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
