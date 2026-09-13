from __future__ import annotations

from pathlib import Path

# Default relative layout inside the Windows VE (analyst may change in GUI)
DEFAULT_DOWNLOAD_DIR = Path.home() / "SafeWeights" / "inbox"
DEFAULT_REPORTS_DIR = Path.home() / "SafeWeights" / "reports"

# Extensions we attempt to classify / scan
PICKLE_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".dill", ".cloudpickle"}
TORCH_EXTENSIONS = {".pt", ".pth", ".bin", ".ckpt"}
SAFETENSORS_EXTENSIONS = {".safetensors"}
GGUF_EXTENSIONS = {".gguf"}
ONNX_EXTENSIONS = {".onnx"}
H5_EXTENSIONS = {".h5", ".hdf5", ".keras"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz"}

SCANNABLE_EXTENSIONS = (
    PICKLE_EXTENSIONS
    | TORCH_EXTENSIONS
    | SAFETENSORS_EXTENSIONS
    | GGUF_EXTENSIONS
    | ONNX_EXTENSIONS
    | H5_EXTENSIONS
)

# Known-dangerous pickle import targets (module.attr patterns and module prefixes)
DANGEROUS_PICKLE_IMPORTS: dict[str, str] = {
    # CRITICAL — direct code execution / process control
    "builtins.exec": "CRITICAL",
    "builtins.eval": "CRITICAL",
    "builtins.compile": "CRITICAL",
    "builtins.__import__": "CRITICAL",
    "builtins.open": "HIGH",
    "builtins.breakpoint": "HIGH",
    "os.system": "CRITICAL",
    "os.popen": "CRITICAL",
    "os.exec": "CRITICAL",
    "os.execl": "CRITICAL",
    "os.execle": "CRITICAL",
    "os.execlp": "CRITICAL",
    "os.execlpe": "CRITICAL",
    "os.execv": "CRITICAL",
    "os.execve": "CRITICAL",
    "os.execvp": "CRITICAL",
    "os.execvpe": "CRITICAL",
    "os.spawn": "CRITICAL",
    "os.posix_spawn": "CRITICAL",
    "os.remove": "HIGH",
    "os.unlink": "HIGH",
    "os.rename": "HIGH",
    "os.replace": "HIGH",
    "subprocess": "CRITICAL",
    "subprocess.call": "CRITICAL",
    "subprocess.run": "CRITICAL",
    "subprocess.Popen": "CRITICAL",
    "subprocess.check_output": "CRITICAL",
    "commands.getoutput": "CRITICAL",
    "pty.spawn": "CRITICAL",
    "code.InteractiveInterpreter": "CRITICAL",
    "code.InteractiveConsole": "CRITICAL",
    "codeop": "CRITICAL",
    # HIGH — network / native / import machinery
    "socket": "HIGH",
    "ctypes": "HIGH",
    "cffi": "HIGH",
    "importlib": "HIGH",
    "runpy": "HIGH",
    "sys.modules": "HIGH",
    "http.client": "HIGH",
    "http.server": "HIGH",
    "urllib.request": "HIGH",
    "requests": "HIGH",
    "webbrowser": "MEDIUM",
    "shutil.rmtree": "HIGH",
    "pathlib.Path": "MEDIUM",
    "tempfile": "MEDIUM",
    "multiprocessing": "HIGH",
    "threading.Thread": "MEDIUM",
    "pickle": "MEDIUM",
    "dill": "MEDIUM",
    "cloudpickle": "MEDIUM",
    "marshal": "HIGH",
    "numpy.fromfile": "MEDIUM",
    "numpy.fromstring": "MEDIUM",
    "torch.load": "HIGH",
    "torch.save": "LOW",
}

# Modules whose mere presence as GLOBAL is at least MEDIUM unless allowlisted
SENSITIVE_MODULE_PREFIXES = (
    "os",
    "subprocess",
    "sys",
    "socket",
    "ctypes",
    "importlib",
    "builtins",
    "code",
    "runpy",
    "pty",
    "commands",
    "multiprocessing",
    "http",
    "urllib",
    "asyncio",
)

# Common torch/numpy reconstruction helpers — noted but usually expected
ALLOWLISTED_PICKLE_IMPORTS = {
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_device_tensor",
    "torch.FloatStorage",
    "torch.DoubleStorage",
    "torch.HalfStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.ShortStorage",
    "torch.CharStorage",
    "torch.ByteStorage",
    "torch.BoolStorage",
    "torch.BFloat16Storage",
    "torch.Size",
    "torch.device",
    "torch.dtype",
    "torch.Tensor",
    "torch.nn.modules.module._load_from_state_dict",
    "collections.OrderedDict",
    "collections.defaultdict",
    "numpy.core.multiarray._reconstruct",
    "numpy.core.multiarray.scalar",
    "numpy.dtype",
    "numpy.ndarray",
    "_codecs.encode",
    "copyreg._reconstructor",
}
