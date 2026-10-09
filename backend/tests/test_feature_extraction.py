from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.traffic.models import TrafficPacket, TCPFlags, FlowKey
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features, calculate_entropy
from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.analyze_pcap import analyze_pcap_file
from tests.fixtures.generate_sample_pcap import generate_test_pcap

client = TestClient(app)


@pytest.fixture(scope="session")
def sample_pcap_path(tmp_path_factory) -> Path:
    pcap_dir = tmp_path_factory.mktemp("pcap_data")
    pcap_file = pcap_dir / "test_capture.pcap"
    generate_test_pcap(pcap_file)
    return pcap_file


def test_calculate_entropy():
    assert calculate_entropy([100, 100, 100, 100]) == 0.0
    assert calculate_entropy([]) == 0.0
    assert calculate_entropy([10, 20]) == 1.0
    assert calculate_entropy([10, 20, 30, 40]) == 2.0


def test_packet_parsing(sample_pcap_path: Path):
    packets = list(read_pcap_packets(sample_pcap_path))
    assert len(packets) == 12

    p0 = packets[0]
    assert p0.src_ip == "192.0.2.10"
    assert p0.dst_ip == "192.0.2.80"
    assert p0.src_port == 49152
    assert p0.dst_port == 80
    assert p0.protocol == "TCP"
    assert p0.tcp_flags is not None
    assert p0.tcp_flags.syn is True
    assert p0.tcp_flags.ack is False


def test_unidirectional_flow_aggregation(sample_pcap_path: Path):
    packets = list(read_pcap_packets(sample_pcap_path))
    flows = aggregate_unidirectional_flows(packets)

    assert len(flows) == 4

    flow1 = next(f for f in flows if f.key.src_ip == "192.0.2.10" and f.key.dst_port == 80)
    assert flow1.packet_count == 4
    assert flow1.duration == pytest.approx(0.5, abs=0.001)

    flow2 = next(f for f in flows if f.key.src_ip == "192.0.2.25" and f.key.dst_port == 443)
    assert flow2.packet_count == 5
    assert flow2.duration == pytest.approx(4.0, abs=0.001)


def test_feature_extraction_accuracy(sample_pcap_path: Path):
    result = analyze_pcap_file(sample_pcap_path)
    assert result.total_packets_parsed == 12
    assert result.total_unidirectional_flows == 4

    # 1. Flow A (Web Traffic)
    f_web = next(f for f in result.flows if f.src_ip == "192.0.2.10")
    assert f_web.protocol == "TCP"
    assert f_web.packet_count == 4
    assert f_web.duration_seconds == 0.5
    assert f_web.packets_per_second == 8.0
    assert f_web.syn_count == 1
    assert f_web.ack_count == 3
    assert f_web.fin_count == 1
    assert f_web.syn_ratio == 0.25
    assert f_web.ack_ratio == 0.75
    assert f_web.is_well_known_dst_port is True
    assert f_web.is_ephemeral_src_port is True

    # 2. Flow B (C2 Beaconing - Periodic rhythmic intervals)
    f_c2 = next(f for f in result.flows if f.src_ip == "192.0.2.25")
    assert f_c2.packet_count == 5
    assert f_c2.duration_seconds == 4.0
    assert f_c2.mean_iat_seconds == 1.0
    assert f_c2.std_iat_seconds == 0.0
    assert f_c2.iat_jitter_seconds == 0.0
    assert f_c2.burstiness_ratio == 0.0
    assert f_c2.packet_size_entropy == 0.0

    # 3. Flow C (UDP Flow)
    f_udp = next(f for f in result.flows if f.src_ip == "192.0.2.33")
    assert f_udp.protocol == "UDP"
    assert f_udp.packet_count == 2
    assert f_udp.dst_port == 53
    assert f_udp.syn_count == 0
    assert f_udp.syn_ratio == 0.0

    # 4. Flow D (Single SYN Probe)
    f_scan = next(f for f in result.flows if f.src_ip == "192.0.2.44")
    assert f_scan.packet_count == 1
    assert f_scan.duration_seconds == 0.0
    assert f_scan.syn_count == 1
    assert f_scan.syn_ratio == 1.0


def test_deterministic_extraction(sample_pcap_path: Path):
    res1 = analyze_pcap_file(sample_pcap_path)
    res2 = analyze_pcap_file(sample_pcap_path)

    assert res1.total_packets_parsed == res2.total_packets_parsed
    assert res1.total_unidirectional_flows == res2.total_unidirectional_flows
    assert len(res1.flows) == len(res2.flows)

    for f1, f2 in zip(res1.flows, res2.flows):
        assert f1.as_vector() == f2.as_vector()
        assert f1.flow_id == f2.flow_id


def test_api_pcap_upload_endpoint(sample_pcap_path: Path):
    with open(sample_pcap_path, "rb") as f:
        response = client.post(
            "/api/traffic/extract-pcap",
            files={"file": ("sample.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_packets_parsed"] == 12
    assert data["total_unidirectional_flows"] == 4
    assert len(data["flows"]) == 4
    assert data["summary"]["status"] == "success"
