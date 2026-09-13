from __future__ import annotations

import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import Any

ProgressCb = Callable[[str], None]
DeviceInfoCb = Callable[[dict[str, Any]], None]


def _missing_hub(exc: BaseException) -> None:
    raise RuntimeError(
        "huggingface_hub is not installed. Run: python -m pip install huggingface_hub"
    ) from exc


def get_hf_token() -> str | None:
    """Return the active Hugging Face token from the local hub cache, if any."""
    try:
        from huggingface_hub import get_token
    except ImportError as exc:
        _missing_hub(exc)
    return get_token()


def hf_whoami(token: str | None = None) -> dict[str, Any] | None:
    """
    Return hub account info for the given token (or the cached session).
    Returns None when not signed in.
    """
    try:
        from huggingface_hub import HfApi
        from huggingface_hub.utils import HfHubHTTPError
    except ImportError as exc:
        _missing_hub(exc)

    resolved = token or get_hf_token()
    if not resolved:
        return None
    try:
        return HfApi().whoami(token=resolved)
    except HfHubHTTPError:
        return None
    except Exception:  # noqa: BLE001 — treat any auth failure as signed-out
        return None


def _login_with_token(token: str) -> dict[str, Any]:
    try:
        from huggingface_hub import login
    except ImportError as exc:
        _missing_hub(exc)

    # Stores token in the HF cache only (not in reports/logs).
    login(token=token, add_to_git_credential=False)
    info = hf_whoami(token=token)
    if not info:
        raise RuntimeError("Login saved but account lookup failed. Check the token and try again.")
    return info


def _login_device_flow(
    *,
    on_device_info: DeviceInfoCb | None = None,
    open_browser: bool = True,
    on_pending: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """
    Run the same OAuth device/browser flow as `hf auth login` / `huggingface-cli login`.

    Uses huggingface_hub's device-code helpers (request URL + user code, poll, save).
    """
    try:
        # Same internals the CLI uses when no token is pasted.
        from huggingface_hub._login import (  # type: ignore[attr-defined]
            _save_oauth_token,
            poll_device_token,
            request_device_code,
        )
    except ImportError as exc:
        _missing_hub(exc)

    device_info = request_device_code()
    # Normalize keys the GUI needs; hub already sets verification_uri_complete when possible.
    url = str(device_info.get("verification_uri_complete") or device_info.get("verification_uri") or "")
    user_code = str(device_info.get("user_code") or "")
    if on_device_info is not None:
        on_device_info(
            {
                "verification_uri": str(device_info.get("verification_uri") or ""),
                "verification_uri_complete": url,
                "user_code": user_code,
                "expires_in": device_info.get("expires_in"),
                "interval": device_info.get("interval"),
            }
        )
    if open_browser and url:
        webbrowser.open(url)

    response = poll_device_token(device_info, on_pending=on_pending)
    try:
        _save_oauth_token(response)
    except Exception:
        # Fallback: persist access token via public login() if OAuth saver shape changes.
        access = response.get("access_token")
        if not access:
            raise
        _login_with_token(str(access))
        return hf_whoami() or {}

    info = hf_whoami()
    if not info:
        raise RuntimeError("Device login completed but account lookup failed. Try Refresh status.")
    return info


def hf_login(
    token: str | None = None,
    *,
    on_device_info: DeviceInfoCb | None = None,
    open_browser: bool = True,
    on_pending: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """
    Sign in to Hugging Face.

    Default: device/browser link flow (same as `hf auth login`).
    Optional token: paste-token path for air-gapped / advanced use only.
    Never logs the token.
    """
    cleaned = (token or "").strip()
    if cleaned:
        return _login_with_token(cleaned)
    return _login_device_flow(
        on_device_info=on_device_info,
        open_browser=open_browser,
        on_pending=on_pending,
    )


def hf_logout() -> None:
    """Clear the local Hugging Face hub session token."""
    try:
        from huggingface_hub import logout
    except ImportError as exc:
        _missing_hub(exc)
    logout()


def display_name_from_whoami(info: dict[str, Any] | None) -> str | None:
    """Pick a human-readable account label from whoami payload."""
    if not info:
        return None
    for key in ("name", "fullname", "email"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def download_model(
    model_id: str,
    dest_dir: Path,
    token: str | None = None,
    progress: ProgressCb | None = None,
) -> Path:
    """
    Pull a Hugging Face model repo into dest_dir/<sanitized_id>.
    Uses huggingface_hub (same backend as huggingface-cli).

    When token is omitted, uses the logged-in hub session / cached token automatically.
    """
    model_id = model_id.strip().strip("/")
    if not model_id:
        raise ValueError("Model ID is required (example: google/gemma-2-9b-it)")

    dest_dir = dest_dir.expanduser().resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    local_dir = dest_dir / model_id.replace("/", "__")
    local_dir.mkdir(parents=True, exist_ok=True)

    def log(msg: str) -> None:
        if progress:
            progress(msg)

    log(f"Starting download: {model_id}")
    log(f"Target folder: {local_dir}")

    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        _missing_hub(exc)

    # Prefer explicit one-off override; otherwise rely on cached login session.
    resolved = (token or "").strip() or get_hf_token()
    kwargs: dict = {
        "repo_id": model_id,
        "local_dir": str(local_dir),
    }
    if resolved:
        kwargs["token"] = resolved
        log("Using Hugging Face credentials (token not logged).")
    else:
        log("No Hugging Face login detected — attempting anonymous download.")

    path = snapshot_download(**kwargs)
    log(f"Download complete: {path}")
    return Path(path)
