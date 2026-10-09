import sys
import json
import argparse
from pathlib import Path
from typing import Optional, Union, Dict, Any

from .models import PCAPAnalysisResult
from .pcap_parser import read_pcap_packets
from .flow_aggregator import aggregate_unidirectional_flows
from .feature_extractor import extract_features_from_flows


def analyze_pcap_file(
    pcap_path: Union[str, Path],
    min_packets: int = 1,
    idle_timeout_seconds: Optional[float] = None,
) -> PCAPAnalysisResult:
    """
    Complete end-to-end passive pipeline:
    PCAP file -> TrafficPacket stream -> Unidirectional TrafficFlows -> FlowFeatures.
    """
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    # 1. Parse packets
    raw_packets = list(read_pcap_packets(path))
    total_packets = len(raw_packets)

    if total_packets == 0:
        return PCAPAnalysisResult(
            pcap_filename=path.name,
            total_packets_parsed=0,
            total_unidirectional_flows=0,
            total_bytes=0,
            capture_duration_seconds=0.0,
            flows=[],
            summary={"message": "No valid IP packets observed in PCAP."},
        )

    # 2. Aggregate unidirectional flows
    flows = aggregate_unidirectional_flows(raw_packets, idle_timeout_seconds=idle_timeout_seconds)

    # Filter flows by minimum packet count if requested
    if min_packets > 1:
        flows = [f for f in flows if f.packet_count >= min_packets]

    # 3. Extract numerical flow features
    extracted_features = extract_features_from_flows(flows)

    # Compute high-level capture statistics
    timestamps = [p.timestamp for p in raw_packets]
    capture_start = min(timestamps)
    capture_end = max(timestamps)
    total_bytes = sum(p.length for p in raw_packets)
    capture_duration = round(max(0.0, capture_end - capture_start), 6)

    protocols_count: Dict[str, int] = {}
    for f in extracted_features:
        protocols_count[f.protocol] = protocols_count.get(f.protocol, 0) + 1

    summary: Dict[str, Any] = {
        "status": "success",
        "capture_start": round(capture_start, 6),
        "capture_end": round(capture_end, 6),
        "protocols_breakdown": protocols_count,
        "avg_packets_per_flow": round(total_packets / len(flows), 2) if flows else 0.0,
        "avg_bytes_per_flow": round(total_bytes / len(flows), 2) if flows else 0.0,
    }

    return PCAPAnalysisResult(
        pcap_filename=path.name,
        total_packets_parsed=total_packets,
        total_unidirectional_flows=len(extracted_features),
        total_bytes=total_bytes,
        capture_duration_seconds=capture_duration,
        flows=extracted_features,
        summary=summary,
    )


def main():
    """CLI runner for offline PCAP feature extraction."""
    parser = argparse.ArgumentParser(
        description="UNIGUARD AI (SIH26145) - Offline PCAP Passive Flow Feature Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python -m app.traffic.analyze_pcap /path/to/capture.pcap
  python -m app.traffic.analyze_pcap capture.pcap --output features.json --indent 2
        """
    )
    parser.add_argument("pcap", help="Path to offline PCAP/PCAPNG capture file")
    parser.add_argument("--output", "-o", help="Optional output JSON file path", default=None)
    parser.add_argument("--min-packets", "-m", type=int, default=1, help="Minimum packet count per flow (default: 1)")
    parser.add_argument("--idle-timeout", "-t", type=float, default=None, help="Flow idle split timeout in seconds")
    parser.add_argument("--indent", "-i", type=int, default=2, help="JSON indentation level")

    args = parser.parse_args()

    try:
        result = analyze_pcap_file(
            pcap_path=args.pcap,
            min_packets=args.min_packets,
            idle_timeout_seconds=args.idle_timeout,
        )

        json_output = result.model_dump_json(indent=args.indent)

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w") as f:
                f.write(json_output)
            print(f"[UNIGUARD AI] Features exported successfully to: {out_path} ({len(result.flows)} flows)")
        else:
            print(json_output)

    except Exception as e:
        print(f"[ERROR] PCAP analysis failed: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
