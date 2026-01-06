import json
import os
from typing import Any, Dict, Tuple

from .utils import run_cmd, which

AI_KEYWORDS = [
    "generated", "generative", "ai", "stable diffusion", "midjourney", "dall-e", "dalle",
    "gemini", "imagen", "firefly", "sora", "runway", "pika", "leonardo",
]

from datetime import datetime

TIMELINE_KEYS = [
    "EXIF:DateTimeOriginal", "EXIF:CreateDate", "EXIF:ModifyDate",
    "XMP:CreateDate", "XMP:ModifyDate",
    "File:FileCreateDate", "File:FileModifyDate",
]

def derived_timeline(meta: Dict[str, Any]) -> Dict[str, Any]:
    tl = {"events": [], "notes": []}
    if not isinstance(meta, dict):
        return tl
    for k in TIMELINE_KEYS:
        v = meta.get(k)
        if v:
            tl["events"].append({"key": k, "value": str(v)})
    if not tl["events"]:
        tl["notes"].append("No usable timestamp fields found in extracted metadata.")
    # sort heuristically by key priority (not true chronological parsing)
    return tl

def metadata_consistency(meta: Dict[str, Any]) -> Dict[str, Any]:
    c = {"status": "UNKNOWN", "checks": [], "notes": []}
    if not isinstance(meta, dict):
        return c
    # Basic checks: presence and agreement between common time fields
    dt1 = meta.get("EXIF:DateTimeOriginal") or meta.get("EXIF:CreateDate")
    dt2 = meta.get("XMP:CreateDate")
    if dt1 and dt2:
        same = str(dt1).split("+")[0].strip() == str(dt2).split("+")[0].strip()
        c["checks"].append({"name": "EXIF vs XMP create time", "exif": str(dt1), "xmp": str(dt2), "consistent": same})
    make = meta.get("EXIF:Make") or meta.get("Make")
    model = meta.get("EXIF:Model") or meta.get("Model")
    if make or model:
        c["checks"].append({"name": "Device identifiers present", "make": str(make or ""), "model": str(model or ""), "consistent": True})
    else:
        c["checks"].append({"name": "Device identifiers present", "consistent": False})
        c["notes"].append("No camera Make/Model present. This often happens after export, screenshot, or platform processing.")
    # Determine status
    if any(ch.get("consistent") is False for ch in c["checks"] if "consistent" in ch):
        c["status"] = "INCONSISTENT_OR_MISSING"
    elif c["checks"]:
        c["status"] = "CONSISTENT"
    return c
def tool_versions() -> Dict[str, Dict[str, Any]]:
    tools = {}
    for t, cmd in {
        "exiftool": ["exiftool", "-ver"],
        "ffprobe": ["ffprobe", "-version"],
        "c2patool": ["c2patool", "--version"],
    }.items():
        code, out, err = run_cmd(cmd, timeout=10)
        tools[t] = {
            "available": (code == 0),
            "version": out.splitlines()[0] if out else None,
            "notes": None if code == 0 else (err[:200] if err else "Unavailable"),
        }
    return tools

def detect_media_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in [".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff", ".heic", ".heif", ".bmp", ".gif"]:
        return "image"
    if ext in [".mp4", ".mov", ".m4v", ".mkv", ".webm", ".avi", ".3gp"]:
        return "video"
    if which("ffprobe"):
        code, out, _ = run_cmd(["ffprobe", "-v", "error", "-show_entries", "format=format_name", "-of", "json", path], timeout=15)
        if code == 0 and out:
            try:
                j = json.loads(out)
                fmt = (j.get("format", {}) or {}).get("format_name", "")
                if fmt and any(x in fmt for x in ["mp4", "mov", "matroska", "webm", "avi", "3gp"]):
                    return "video"
            except Exception:
                pass
    return "unknown"

def extract_exiftool(path: str) -> Dict[str, Any]:
    if not which("exiftool"):
        return {"_status": "missing_exiftool"}
    code, out, err = run_cmd(["exiftool", "-json", "-G", "-a", "-s", path], timeout=25)
    if code != 0:
        return {"_status": "error", "_error": err[:400]}
    try:
        arr = json.loads(out)
        return arr[0] if arr else {"_status": "empty"}
    except Exception:
        return {"_status": "parse_error"}

def extract_ffprobe(path: str) -> Dict[str, Any]:
    if not which("ffprobe"):
        return {"_status": "missing_ffprobe"}
    code, out, err = run_cmd(["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", path], timeout=25)
    if code != 0:
        return {"_status": "error", "_error": err[:400]}
    try:
        return json.loads(out)
    except Exception:
        return {"_status": "parse_error"}

def extract_c2pa(path: str) -> Dict[str, Any]:
    if not which("c2patool"):
        return {"_status": "missing_c2patool"}
    code, out, err = run_cmd(["c2patool", "--json", path], timeout=30)
    if code == 0 and out:
        try:
            return json.loads(out)
        except Exception:
            return {"_status": "parse_error", "raw": out[:2000]}
    code2, out2, err2 = run_cmd(["c2patool", path], timeout=30)
    if code2 != 0:
        return {"_status": "error", "_error": (err or err2)[:800]}
    return {"_status": "text_only", "raw": out2[:4000]}

def ai_disclosure_from_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    if not meta or meta.get("_status") in {"missing_exiftool", "error", "parse_error"}:
        return {"declared": "UNKNOWN", "signals": [], "notes": "No reliable metadata to scan."}

    hay = json.dumps(meta, ensure_ascii=False).lower()
    signals = [kw for kw in AI_KEYWORDS if kw in hay]

    interesting_fields = []
    for k in meta.keys():
        lk = k.lower()
        if any(x in lk for x in ["software", "creator", "producer", "xmp", "history", "edit", "ai"]):
            interesting_fields.append(k)

    declared = "NO"
    notes = "No AI disclosure markers found in available metadata."
    if signals:
        declared = "POSSIBLE"
        notes = "AI-related markers were found in metadata text. This can indicate disclosure or editing trace, not definitive origin."
    return {
        "declared": declared,
        "signals": sorted(set(signals)),
        "interesting_fields": sorted(set(interesting_fields))[:30],
        "notes": notes,
    }

def transformation_hints(meta: Dict[str, Any], ff: Dict[str, Any]) -> Dict[str, Any]:
    hints: Dict[str, Any] = {
        "screenshot_likelihood": "UNKNOWN",
        "forwarded_or_reencoded": "UNKNOWN",
        "notes": [],
    }

    make = meta.get("EXIF:Make") or meta.get("Make")
    model = meta.get("EXIF:Model") or meta.get("Model")
    software = meta.get("XMP:CreatorTool") or meta.get("EXIF:Software") or meta.get("Software") or ""
    sw_l = str(software).lower()

    if not make and not model and ("screenshot" in sw_l or "screen" in sw_l):
        hints["screenshot_likelihood"] = "HIGH"
        hints["notes"].append("Metadata suggests screen-capture tools and lacks camera Make/Model.")
    elif make or model:
        hints["screenshot_likelihood"] = "LOW"

    if ff and ff.get("_status") not in {"missing_ffprobe", "error", "parse_error"}:
        fmt_tags = (ff.get("format", {}) or {}).get("tags", {}) or {}
        encoder = fmt_tags.get("encoder") or fmt_tags.get("ENCODER")
        if encoder:
            hints["forwarded_or_reencoded"] = "POSSIBLE"
            hints["notes"].append(f"Container tag indicates encoder: {encoder}")

    if hints["screenshot_likelihood"] == "UNKNOWN" and hints["forwarded_or_reencoded"] == "UNKNOWN":
        hints["notes"].append("No strong transformation clues detected from available signals.")
    return hints

def classify_provenance(c2pa: Dict[str, Any], meta: Dict[str, Any]) -> Tuple[str, str]:
    state = "UNVERIFIABLE_NO_PROVENANCE"
    summary = "No cryptographic provenance proof was found (no usable C2PA manifest)."

    if c2pa and c2pa.get("_status") not in {"missing_c2patool", "error"}:
        js = json.dumps(c2pa, ensure_ascii=False).lower()
        has_manifest = ("manifest" in js) or ("c2pa" in js)
        looks_valid = (("valid" in js) or ("verified" in js) or ("passed" in js)) and not (("failed" in js) or ("invalid" in js) or ("broken" in js))
        looks_failed = ("failed" in js) or ("invalid" in js) or ("broken" in js)

        if has_manifest and looks_valid:
            state = "VERIFIED_ORIGINAL"
            summary = "C2PA manifest detected and validation signals indicate an intact trust chain."
        elif has_manifest and looks_failed:
            state = "ALTERED_OR_BROKEN_PROVENANCE"
            summary = "C2PA manifest detected but validation signals indicate a broken or altered trust chain."
        elif has_manifest:
            state = "ALTERED_OR_BROKEN_PROVENANCE"
            summary = "C2PA manifest detected, but validation status could not be confirmed. Treat as potentially altered."
        else:
            state = "UNVERIFIABLE_NO_PROVENANCE"
            summary = "No C2PA manifest detected in the provided media."

    return state, summary


def metadata_completeness(meta: dict) -> dict:
    """Returns a 0–3 completeness score for common provenance-relevant metadata fields.
    This is NOT a trust score; it is only a visibility/completeness indicator."""
    meta = meta or {}
    exif = (meta.get("exif") or {}) if isinstance(meta.get("exif"), dict) else {}
    xmp = (meta.get("xmp") or {}) if isinstance(meta.get("xmp"), dict) else {}

    def _get(d, *keys):
        for k in keys:
            v = d.get(k)
            if v not in (None, "", "Unknown", "unknown"):
                return v
        return None

    # Camera/device
    make = _get(exif, "Make", "make")
    model = _get(exif, "Model", "model")

    # Time
    dt = _get(exif, "DateTimeOriginal", "CreateDate", "ModifyDate") or _get(xmp, "CreateDate", "ModifyDate", "DateCreated")

    # Location
    lat = _get(exif, "GPSLatitude", "gpsLatitude")
    lon = _get(exif, "GPSLongitude", "gpsLongitude")

    checks = {
        "camera_make_model_present": bool(make or model),
        "timestamp_present": bool(dt),
        "location_present": bool(lat and lon),
    }
    score = sum(1 for v in checks.values() if v)
    notes = []
    if not checks["camera_make_model_present"]:
        notes.append("No camera Make/Model found (common after exports, screenshots, or platform processing).")
    if not checks["timestamp_present"]:
        notes.append("No creation timestamp found in standard fields.")
    if not checks["location_present"]:
        notes.append("No GPS location found in standard fields.")

    return {
        "score_0_to_3": score,
        "checks": checks,
        "notes": notes,
    }
