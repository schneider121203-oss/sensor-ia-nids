import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import dpkt
import pandas as pd
from nfstream import NFStreamer


SENSOR_DIR = Path(__file__).resolve().parents[1] / "sensor"
sys.path.insert(0, str(SENSOR_DIR))

from feature_contract import (
    MODEL_FEATURES,
    FlowContextWindow,
    build_common_features,
    schema_hash,
)
from flow_monitor import nfstream_to_df
from nfstream_extractor import FirstTTLPlugin, NFStreamFeatureExtractor


def base_record():
    return {
        "dur": 2.0,
        "proto": 6,
        "spkts": 4,
        "dpkts": 2,
        "sbytes": 400,
        "dbytes": 100,
        "sttl": 64,
        "dttl": 63,
        "ct_dst_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 1,
        "ct_src_ltm": 1,
        "is_sm_ips_ports": 0,
    }


class FeatureContractTests(unittest.TestCase):
    def test_contract_is_strict_and_deterministic(self):
        features = build_common_features(pd.DataFrame([base_record()]))
        self.assertEqual(features.columns.tolist(), MODEL_FEATURES)
        self.assertEqual(features.loc[0, "proto"], "tcp")
        self.assertEqual(features.loc[0, "flow_packet_rate"], 3.0)
        self.assertEqual(features.loc[0, "src_load_bps"], 1600.0)
        self.assertEqual(features.loc[0, "src_mean_packet_bytes"], 100.0)
        self.assertEqual(len(schema_hash()), 64)

        incomplete = base_record()
        incomplete.pop("sttl")
        with self.assertRaisesRegex(ValueError, "sttl"):
            build_common_features(pd.DataFrame([incomplete]))

    def test_context_uses_100_flows_including_current(self):
        context = FlowContextWindow(window_size=3)
        first = context.enrich({"src_ip": "a", "dst_ip": "b", "sport": 1, "dport": 2})
        second = context.enrich({"src_ip": "a", "dst_ip": "b", "sport": 1, "dport": 2})
        context.enrich({"src_ip": "x", "dst_ip": "y", "sport": 8, "dport": 9})
        fourth = context.enrich({"src_ip": "a", "dst_ip": "b", "sport": 1, "dport": 2})
        self.assertEqual(first["ct_dst_src_ltm"], 1)
        self.assertEqual(second["ct_dst_src_ltm"], 2)
        # El primer flujo ya salio de la ventana de tamano 3.
        self.assertEqual(fourth["ct_dst_src_ltm"], 2)

    def test_nfstream_row_has_every_required_base_feature(self):
        flow = SimpleNamespace(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=80,
            protocol=6,
            bidirectional_duration_ms=250,
            src2dst_packets=3,
            dst2src_packets=2,
            src2dst_bytes=180,
            dst2src_bytes=120,
            udps=SimpleNamespace(src2dst_first_ttl=64, dst2src_first_ttl=63),
        )
        row = NFStreamFeatureExtractor().extract(flow)
        features = build_common_features(pd.DataFrame([row]))
        self.assertFalse(features.isna().any().any())
        self.assertEqual(row["sttl"], 64)
        self.assertEqual(row["dttl"], 63)


class PcapParityTests(unittest.TestCase):
    @staticmethod
    def _packet(src, dst, sport, dport, ttl, flags, sequence):
        tcp = dpkt.tcp.TCP(
            sport=sport, dport=dport, seq=sequence, flags=flags, win=8192
        )
        ip = dpkt.ip.IP(
            src=socket.inet_aton(src),
            dst=socket.inet_aton(dst),
            ttl=ttl,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp,
        )
        ip.len = len(ip)
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x01\x02\x03\x04\x05",
            dst=b"\x06\x07\x08\x09\x0a\x0b",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        return bytes(eth)

    def test_pcap_and_live_path_produce_identical_features(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap_path = Path(directory) / "parity.pcap"
            with pcap_path.open("wb") as pcap_file:
                writer = dpkt.pcap.Writer(pcap_file)
                writer.writepkt(
                    self._packet("10.0.0.1", "10.0.0.2", 40000, 80, 64, dpkt.tcp.TH_SYN, 1),
                    ts=1.0,
                )
                writer.writepkt(
                    self._packet("10.0.0.2", "10.0.0.1", 80, 40000, 63, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, 2),
                    ts=1.1,
                )
                writer.writepkt(
                    self._packet("10.0.0.1", "10.0.0.2", 40000, 80, 64, dpkt.tcp.TH_ACK, 3),
                    ts=1.2,
                )
                writer.close()

            offline_stream = NFStreamer(
                source=str(pcap_path), statistical_analysis=True, udps=[FirstTTLPlugin()]
            )
            offline = nfstream_to_df(offline_stream)

            live_extractor = NFStreamFeatureExtractor()
            live_stream = NFStreamer(
                source=str(pcap_path), statistical_analysis=True, udps=[FirstTTLPlugin()]
            )
            live = pd.DataFrame([live_extractor.extract(flow) for flow in live_stream])

        pd.testing.assert_frame_equal(
            build_common_features(offline).reset_index(drop=True),
            build_common_features(live).reset_index(drop=True),
            check_exact=True,
        )
        self.assertEqual(int(offline.loc[0, "sttl"]), 64)
        self.assertEqual(int(offline.loc[0, "dttl"]), 63)


if __name__ == "__main__":
    unittest.main()
