import io
import hashlib
from pathlib import Path
import httpx


def download_ctu13_neris_pcap(max_bytes: int = 15 * 1024 * 1024):
    out_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "ctu13_scenario1_neris.pcap"

    if out_file.exists() and out_file.stat().st_size > 0:
        print(f"[EXISTS] ctu13_scenario1_neris.pcap ({out_file.stat().st_size / 1024 / 1024:.2f} MB)")
        return out_file

    url = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"
    print(f"[DOWNLOADING] Streaming authentic CTU-13 Scenario 1 Neris PCAP ({max_bytes / 1024 / 1024:.2f} MB slice)...")

    hasher = hashlib.sha256()
    with httpx.Client(timeout=60.0, follow_redirects=True) as client:
        headers = {"Range": f"bytes=0-{max_bytes - 1}"}
        resp = client.get(url, headers=headers)
        data = resp.content
        with open(out_file, "wb") as f:
            f.write(data)
        hasher.update(data)

    print(f"  Saved: ctu13_scenario1_neris.pcap ({out_file.stat().st_size / 1024 / 1024:.2f} MB, SHA-256: {hasher.hexdigest()})")
    return out_file


if __name__ == "__main__":
    download_ctu13_neris_pcap()
