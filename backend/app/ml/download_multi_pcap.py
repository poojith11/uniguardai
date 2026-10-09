import io
import hashlib
import zipfile
from pathlib import Path
import httpx


class HTTPRangeIO(io.RawIOBase):
    def __init__(self, url: str):
        self.url = url
        resp = httpx.head(url, timeout=30.0)
        self.size = int(resp.headers["content-length"])
        self.pos = 0
        self.client = httpx.Client(timeout=60.0)

    def readable(self) -> bool: return True
    def seekable(self) -> bool: return True
    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET: self.pos = offset
        elif whence == io.SEEK_CUR: self.pos += offset
        elif whence == io.SEEK_END: self.pos = self.size + offset
        return self.pos
    def tell(self) -> int: return self.pos
    def readinto(self, b) -> int:
        l = len(b)
        if self.pos >= self.size: return 0
        end = min(self.size - 1, self.pos + l - 1)
        resp = self.client.get(self.url, headers={"Range": f"bytes={self.pos}-{end}"})
        data = resp.content
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def download_selected_pcaps():
    out_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        # (day_folder, internal_zip_path, local_filename, description)
        (
            "Wednesday-14-02-2018",
            "pcap/UCAP172.31.69.27",
            "UCAP172.31.69.27_Wed14.pcap",
            "Wednesday 14-02-2018 Server Pool Subnet (5.31 MB)"
        ),
        (
            "Thursday-15-02-2018",
            "pcap/UCAP172.31.69.21",
            "UCAP172.31.69.21_Thu15.pcap",
            "Thursday 15-02-2018 DoS/DDoS Victim Server Subnet (3.22 MB)"
        ),
        (
            "Friday-02-03-2018",
            "pcap/capWIN-J6GMIG1DQE5-172.31.67.95",
            "capWIN-172.31.67.95_Fri02.pcap",
            "Friday 02-03-2018 Botnet Client Subnet (0.49 MB)"
        ),
    ]

    for day_folder, zip_path, local_name, desc in targets:
        dest = out_dir / local_name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[EXISTS] {local_name} ({dest.stat().st_size / 1024 / 1024:.2f} MB)")
            continue

        url = f"https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/{day_folder}/pcap.zip"
        print(f"[DOWNLOADING] {desc} from {day_folder}...")
        stream = io.BufferedReader(HTTPRangeIO(url), buffer_size=2 * 1024 * 1024)
        zf = zipfile.ZipFile(stream)

        hasher = hashlib.sha256()
        with zf.open(zip_path) as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                hasher.update(chunk)

        print(f"  Saved: {local_name} ({dest.stat().st_size / 1024 / 1024:.2f} MB, SHA-256: {hasher.hexdigest()})")


if __name__ == "__main__":
    download_selected_pcaps()
