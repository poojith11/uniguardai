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
    def seek(self, offset: int, whence=io.SEEK_SET):
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


def download_phase3f_extra_pcaps():
    out_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        (
            "Friday-02-03-2018",
            "pcap/capEC2AMAZ-O4EL3NG-172.31.69.20",
            "capEC2AMAZ-172.31.69.20_Fri02.pcap",
            "Friday 02-03-2018 Server 20 Botnet Day Capture (0.36 MB)"
        )
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
    download_phase3f_extra_pcaps()
