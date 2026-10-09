from pathlib import Path
import pytest
from app.ml.evaluate_real_pcap import map_real_pcap_ground_truth, evaluate_real_pcap_pipeline
from app.traffic.models import FlowFeatures, FlowKey
from app.ml.dataset_schema import ThreatClass


def test_map_real_pcap_ground_truth():
    # Test attacker mapping
    mock_attacker_flow = FlowFeatures(
        flow_id="f1",
        src_ip="18.218.115.60",
        dst_ip="172.31.69.28",
        src_port=50000,
        dst_port=21,
        protocol="TCP",
        start_time=10.0,
        end_time=11.0,
        duration_seconds=1.0,
        packet_count=5,
        byte_count=500,
        packets_per_second=5.0,
        bytes_per_second=500.0,
        mean_packet_size=100.0,
        std_packet_size=10.0,
        min_packet_size=40,
        max_packet_size=150,
        packet_size_entropy=1.0,
        mean_iat_seconds=0.2,
        std_iat_seconds=0.05,
        min_iat_seconds=0.1,
        max_iat_seconds=0.3,
        iat_jitter_seconds=0.02,
        burstiness_ratio=0.25,
        syn_count=1,
        ack_count=4,
        fin_count=0,
        rst_count=0,
        psh_count=1,
        urg_count=0,
        syn_ratio=0.2,
        ack_ratio=0.8,
        rst_ratio=0.0,
        is_well_known_dst_port=True,
        is_ephemeral_src_port=True,
    )
    assert map_real_pcap_ground_truth(mock_attacker_flow) == ThreatClass.RECON_SCAN.value

    # Test internal benign flow mapping
    mock_benign_flow = FlowFeatures(
        flow_id="f2",
        src_ip="172.31.64.10",
        dst_ip="172.31.69.28",
        src_port=49152,
        dst_port=80,
        protocol="TCP",
        start_time=10.0,
        end_time=15.0,
        duration_seconds=5.0,
        packet_count=20,
        byte_count=2000,
        packets_per_second=4.0,
        bytes_per_second=400.0,
        mean_packet_size=100.0,
        std_packet_size=20.0,
        min_packet_size=40,
        max_packet_size=500,
        packet_size_entropy=2.0,
        mean_iat_seconds=0.25,
        std_iat_seconds=0.1,
        min_iat_seconds=0.05,
        max_iat_seconds=0.5,
        iat_jitter_seconds=0.05,
        burstiness_ratio=0.4,
        syn_count=1,
        ack_count=19,
        fin_count=1,
        rst_count=0,
        psh_count=5,
        urg_count=0,
        syn_ratio=0.05,
        ack_ratio=0.95,
        rst_ratio=0.0,
        is_well_known_dst_port=True,
        is_ephemeral_src_port=True,
    )
    assert map_real_pcap_ground_truth(mock_benign_flow) == ThreatClass.BENIGN.value

    # Test unknown external ambient flow mapping
    mock_ambient_flow = FlowFeatures(
        flow_id="f3",
        src_ip="198.51.100.42",
        dst_ip="172.31.69.28",
        src_port=60000,
        dst_port=443,
        protocol="TCP",
        start_time=10.0,
        end_time=10.0,
        duration_seconds=0.0,
        packet_count=1,
        byte_count=40,
        packets_per_second=1.0,
        bytes_per_second=40.0,
        mean_packet_size=40.0,
        std_packet_size=0.0,
        min_packet_size=40,
        max_packet_size=40,
        packet_size_entropy=0.0,
        mean_iat_seconds=0.0,
        std_iat_seconds=0.0,
        min_iat_seconds=0.0,
        max_iat_seconds=0.0,
        iat_jitter_seconds=0.0,
        burstiness_ratio=0.0,
        syn_count=1,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        psh_count=0,
        urg_count=0,
        syn_ratio=1.0,
        ack_ratio=0.0,
        rst_ratio=0.0,
        is_well_known_dst_port=True,
        is_ephemeral_src_port=True,
    )
    assert map_real_pcap_ground_truth(mock_ambient_flow) == "UNKNOWN_EXCLUDED"


def test_real_pcap_evaluation_with_sample_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_offline.pcap"
    models_dir = Path(__file__).parent.parent / "app" / "ml" / "models"

    # Evaluate on the safe local fixture
    res = evaluate_real_pcap_pipeline(fixture_path, models_dir=models_dir)
    assert "accuracy" in res
    assert "macro_f1" in res
    assert "isolation_forest_fpr_benign" in res
    assert res["packets_parsed"] == 12
    assert res["flows_extracted"] == 4
