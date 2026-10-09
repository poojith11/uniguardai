import io
import hashlib
import zipfile
from pathlib import Path
import httpx


class HTTPRangeIO(io.RawIOBase):
    """Seekable stream adapter for remote HTTP Range requests."""
    def __init__(self, url: str):
        self.url = url
        resp = httpx.head(url, timeout=30.0)
        self.size = int(resp.headers["content-length"])
        self.pos = 0
        self.client = httpx.Client(timeout=60.0)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self.pos = offset
        elif whence == io.SEEK_CUR:
            self.pos += offset
        elif whence == io.SEEK_END:
            self.pos = self.size + offset
        return self.pos

    def tell(self) -> int:
        return self.pos

    def readinto(self, b) -> int:
        l = len(b)
        if self.pos >= self.size:
            return 0
        end = min(self.size - 1, self.pos + l - 1)
        resp = self.client.get(self.url, headers={"Range": f"bytes={self.pos}-{end}"})
        data = resp.content
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


def download_official_cic_pcap(
    target_pcap_name: str = "pcap/capEC2AMAZ-O4EL3NG-172.31.69.28",
    output_dir: Path = None,
) -> Path:
    """
    Selectively streams a single authentic PCAP file from the official AWS CSE-CIC-IDS2018 archive
    without downloading the 38.5 GB zip archive.
    """
    out_dir = output_dir or (Path(__file__).parent.parent.parent / "data" / "raw")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / (Path(target_pcap_name).name + ".pcap")

    if out_file.exists() and out_file.stat().st_size > 0:
        print(f"[INFO] Official PCAP already exists locally at: {out_file} ({out_file.stat().st_size / 1024 / 1024:.2f} MB)")
        return out_file

    url = "https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Original%20Network%20Traffic%20and%20Log%20data/Wednesday-14-02-2018/pcap.zip"
    print(f"[1/3] Connecting to official CSE-CIC-IDS2018 AWS S3 repository: {url}")
    stream = io.BufferedReader(HTTPRangeIO(url), buffer_size=4 * 1024 * 1024)
    zf = zipfile.ZipFile(stream)

    print(f"[2/3] Extracting official capture file: '{target_pcap_name}' ({zf.getinfo(target_pcap_name).file_size / 1024 / 1024:.2f} MB uncompressed)...")
    hasher = hashlib.sha256()

    with zf.open(target_pcap_name) as source, open(out_file, "wb") as target:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            target.write(chunk)
            hasher.update(chunk)

    sha256_hash = hasher.hexdigest()
    print(f"[3/3] Download complete! Saved to: {out_file}")
    print(f"      Size: {out_file.stat().st_size / 1024 / 1024:.2f} MB ({out_file.stat().st_size:,} bytes)")
    print(f"      SHA-256: {sha256_hash}")
    return out_file


if __name__ == "__main__":
    download_official_cic_pcap()
