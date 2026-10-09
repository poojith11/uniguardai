from pathlib import Path
import pytest
import numpy as np
from app.ml.evaluate_multi_capture import map_multi_capture_ground_truth, run_multi_capture_evaluation
from app.traffic.models import FlowFeatures
from app.ml.dataset_schema import ThreatClass


def test_map_multi_capture_ground_truth():
    # Test Botnet C2 mapping
    flow_c2 = FlowFeatures(
        flow_id="f1",
        src_ip="172.31.67.95",
        dst_ip="198.51.100.1",
        src_port=49152,
        dst_port=8080,
        protocol="TCP",
        start_time=10.0,
        end_time=15.0,
        duration_seconds=5.0,
        packet_count=5,
        byte_count=600,
        packets_per_second=1.0,
        bytes_per_second=120.0,
        mean_packet_size=120.0,
        std_packet_size=10.0,
        min_packet_size=40,
        max_packet_size=200,
        packet_size_entropy=1.2,
        mean_iat_seconds=1.0,
        std_iat_seconds=0.1,
        min_iat_seconds=0.9,
        max_iat_seconds=1.1,
        iat_jitter_seconds=0.05,
        burstiness_ratio=0.1,
        syn_count=1,
        ack_count=4,
        fin_count=0,
        rst_count=0,
        psh_count=2,
        urg_count=0,
        syn_ratio=0.2,
        ack_ratio=0.8,
        rst_ratio=0.0,
        is_well_known_dst_port=False,
        is_ephemeral_src_port=True,
    )
    assert map_multi_capture_ground_truth(flow_c2, "Fri02_Client95") == ThreatClass.C2_BEACONING.value

    # Test internal benign mapping
    flow_benign = FlowFeatures(
        flow_id="f2",
        src_ip="172.31.65.10",
        dst_ip="172.31.69.25",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        start_time=10.0,
        end_time=10.5,
        duration_seconds=0.5,
        packet_count=6,
        byte_count=1200,
        packets_per_second=12.0,
        bytes_per_second=2400.0,
        mean_packet_size=200.0,
        std_packet_size=50.0,
        min_packet_size=40,
        max_packet_size=500,
        packet_size_entropy=2.1,
        mean_iat_seconds=0.1,
        std_iat_seconds=0.02,
        min_iat_seconds=0.08,
        max_iat_seconds=0.12,
        iat_jitter_seconds=0.01,
        burstiness_ratio=0.2,
        syn_count=1,
        ack_count=5,
        fin_count=1,
        rst_count=0,
        psh_count=2,
        urg_count=0,
        syn_ratio=0.16,
        ack_ratio=0.83,
        rst_ratio=0.0,
        is_well_known_dst_port=True,
        is_ephemeral_src_port=True,
    )
    assert map_multi_capture_ground_truth(flow_benign, "Wed21_WebServer25") == ThreatClass.BENIGN.value


def test_multi_capture_evaluation_pipeline_execution():
    res = run_multi_capture_evaluation()
    assert res["total_packets"] > 30000
    assert res["total_flows"] > 6000
    assert res["evaluated_flows"] >= 200
    # Verify Phase 3D beats Phase 3B in benign false positive rate and aggregate accuracy
    assert res["aggregate_accuracy_3d"] > res["aggregate_accuracy_3b"]
    assert res["benign_fpr_3d"] < res["benign_fpr_3b"]
    assert res["benign_fpr_3d"] == 0.0
    assert res["iso_recall_3d"] > 0.90
