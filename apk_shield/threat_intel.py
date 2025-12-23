# threat_intel.py
# Robust threat intelligence helper for CyberMoranda APK Shield
# UPDATED: Checks ALL APIs simultaneously (Aggressive Mode)

import os
import json
import time
import requests

# Config
CACHE_FN = os.path.join(os.path.dirname(__file__), "hash_db.json")
VT_KEY = os.environ.get("VT_API_KEY")
OTX_KEY = os.environ.get("OTX_API_KEY")
MB_KEY = os.environ.get("MB_API_KEY")
HTTP_TIMEOUT = 5  # Thoda kam kiya taaki teeno run hone me zyada waqt na lage
CACHE_TTL = 60 * 60 * 24 * 7 

def _load_cache():
    try:
        if not os.path.exists(CACHE_FN) or os.path.getsize(CACHE_FN) == 0:
            return {}
        with open(CACHE_FN, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cache(data):
    try:
        with open(CACHE_FN, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def _query_virustotal(sha256):
    if not VT_KEY: return None
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_KEY}
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            stats = j.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            return {"detected": mal > 0, "label": f"VT:{mal} bad", "status": "malicious" if mal > 0 else "clean"}
        elif r.status_code == 404:
            return {"detected": False, "label": "VT:NF", "status": "unknown"}
    except: pass
    return None

def _query_otx(sha256):
    if not OTX_KEY: return None
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general"
        headers = {"X-OTX-API-KEY": OTX_KEY}
        r = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            pulses = j.get("pulse_info", {}).get("count", 0)
            return {"detected": pulses > 0, "label": f"OTX:{pulses} pulses", "status": "known" if pulses > 0 else "clean"}
        elif r.status_code == 404:
            return {"detected": False, "label": "OTX:NF", "status": "unknown"}
    except: pass
    return None

def _query_malwarebazaar(sha256):
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_info", "hash": sha256}
        r = requests.post(url, data=data, timeout=HTTP_TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            if j.get("query_status") == "ok":
                return {"detected": True, "label": "MB:Found", "status": "malicious"}
            else:
                return {"detected": False, "label": "MB:NF", "status": "unknown"}
    except: pass
    return None

def check_hash_reputation(sha256: str):
    sha256 = sha256.lower().strip()
    cache = _load_cache()
    now = int(time.time())

    # Cache Check
    if sha256 in cache:
        entry = cache[sha256]
        if now - entry.get("ts", 0) < CACHE_TTL:
            return {**entry, "cached": True}

    # Query ALL APIs
    results = []
    labels = []
    
    # Run VT
    vt_res = _query_virustotal(sha256)
    if vt_res: 
        results.append(vt_res)
        labels.append(vt_res["label"])
    
    # Run OTX
    otx_res = _query_otx(sha256)
    if otx_res: 
        results.append(otx_res)
        labels.append(otx_res["label"])

    # Run MB
    mb_res = _query_malwarebazaar(sha256)
    if mb_res: 
        results.append(mb_res)
        labels.append(mb_res["label"])

    # Aggregate Decision
    final_status = "unknown"
    is_malicious = any(r["detected"] for r in results)
    
    if is_malicious:
        final_status = "MALICIOUS"
    elif results:
        final_status = "Clean/Unknown"
    
    final_label = " | ".join(labels) if labels else "No Data / API Fail"
    final_source = "Aggregated (VT+OTX+MB)"

    # Save to Cache
    out = {"status": final_status, "source": final_source, "label": final_label, "ts": now}
    cache[sha256] = out
    _save_cache(cache)
    
    return {**out, "cached": False}
