import io
import hashlib
import zipfile
from pathlib import Path
import httpx


class HTTPRangeIO(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        resp = httpx.head(url, follow_redirects=True)
        self.size = int(resp.headers["content-length"])
        self.pos = 0
        self.client = httpx.Client(follow_redirects=True, timeout=30.0)

    def readable(self): return True
    def seekable(self): return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET: self.pos = offset
        elif whence == io.SEEK_CUR: self.pos += offset
        elif whence == io.SEEK_END: self.pos = self.size + offset
        return self.pos

    def tell(self): return self.pos

    def readinto(self, b):
        l = len(b)
        if self.pos >= self.size: return 0
        end = min(self.size - 1, self.pos + l - 1)
        resp = self.client.get(self.url, headers={"Range": f"bytes={self.pos}-{end}"})
        data = resp.content
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def download_fri16_dos_capture():
    out_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "UCAP172.31.69.21_Fri16.pcap"

    if out_file.exists() and out_file.stat().st_size > 0:
        print(f"[EXISTS] UCAP172.31.69.21_Fri16.pcap ({out_file.stat().st_size / 1024 / 1024:.2f} MB)")
        return out_file

    url = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Friday-16-02-2018/pcap.zip"
    print(f"[DOWNLOADING] Streaming UCAP172.31.69.21 from Friday-16-02-2018/pcap.zip...")

    stream = io.BufferedReader(HTTPRangeIO(url), buffer_size=1024 * 1024)
    zf = zipfile.ZipFile(stream)

    target_name = "pcap/UCAP172.31.69.21"
    info = zf.getinfo(target_name)
    print(f"  Found {target_name} ({info.file_size / 1024 / 1024:.2f} MB)")

    hasher = hashlib.sha256()
    with zf.open(info) as src, open(out_file, "wb") as dst:
        while chunk := src.read(512 * 1024):
            dst.write(chunk)
            hasher.update(chunk)

    print(f"  Saved: UCAP172.31.69.21_Fri16.pcap ({out_file.stat().st_size / 1024 / 1024:.2f} MB, SHA-256: {hasher.hexdigest()})")
    return out_file


if __name__ == "__main__":
    download_fri16_dos_capture()
