from unittest import TestCase
from pathlib import Path
import pytest

from boefjes.plugins.kat_nmap.main import Protocol, build_nmap_arguments
from boefjes.job_models import BoefjeMeta, NormalizerMeta
from boefjes.katalogus.local_repository import LocalPluginRepository
from boefjes.local import LocalBoefjeJobRunner, LocalNormalizerJobRunner
from tests.stubs import get_dummy_data


class NmapTest(TestCase):
    def test_nmap_arguments_tcp_top_150(self):
        args = build_nmap_arguments("1.1.1.1", Protocol.TCP, 250)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sS",
                "--top-ports",
                "250",
                "-oX",
                "-",
                "1.1.1.1",
            ],
            args,
        )

    def test_nmap_arguments_tcp_top_150_ipv6(self):
        args = build_nmap_arguments("2001:19f0:5001:23fe:5400:3ff:fe60:883b", Protocol.TCP, 250)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sS",
                "--top-ports",
                "250",
                "-6",
                "-oX",
                "-",
                "2001:19f0:5001:23fe:5400:3ff:fe60:883b",
            ],
            args,
        )

    def test_nmap_arguments_tcp_full(self):
        args = build_nmap_arguments("1.1.1.1", Protocol.TCP, None)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sS",
                "-p-",
                "-oX",
                "-",
                "1.1.1.1",
            ],
            args,
        )

    def test_nmap_arguments_tcp_full_ipv6(self):
        args = build_nmap_arguments("2001:19f0:5001:23fe:5400:3ff:fe60:883b", Protocol.TCP, None)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sS",
                "-p-",
                "-6",
                "-oX",
                "-",
                "2001:19f0:5001:23fe:5400:3ff:fe60:883b",
            ],
            args,
        )

    def test_nmap_arguments_udp_full(self):
        args = build_nmap_arguments("1.1.1.1", Protocol.UDP, None)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sU",
                "-p-",
                "-oX",
                "-",
                "1.1.1.1",
            ],
            args,
        )

    def test_nmap_arguments_udp_full_ipv6(self):
        args = build_nmap_arguments("2001:19f0:5001:23fe:5400:3ff:fe60:883b", Protocol.UDP, None)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sU",
                "-p-",
                "-6",
                "-oX",
                "-",
                "2001:19f0:5001:23fe:5400:3ff:fe60:883b",
            ],
            args,
        )

    def test_nmap_arguments_udp_top250(self):
        args = build_nmap_arguments("1.1.1.1", Protocol.UDP, 250)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sU",
                "--top-ports",
                "250",
                "-oX",
                "-",
                "1.1.1.1",
            ],
            args,
        )

    def test_nmap_arguments_udp_top250_ipv6(self):
        args = build_nmap_arguments("2001:19f0:5001:23fe:5400:3ff:fe60:883b", Protocol.UDP, 250)
        self.assertListEqual(
            [
                "nmap",
                "-T4",
                "-Pn",
                "-r",
                "-v10",
                "-sV",
                "-sU",
                "--top-ports",
                "250",
                "-6",
                "-oX",
                "-",
                "2001:19f0:5001:23fe:5400:3ff:fe60:883b",
            ],
            args,
        )

    @pytest.mark.skipif("not Path(__file__).parent.joinpath('examples/tmp_large_nmap.xml').exists()")
    def test_large_nmap_parsing(self):
        meta = NormalizerMeta.parse_raw(get_dummy_data("nmap-normalizer.json"))
        local_repository = LocalPluginRepository(Path(__file__).parent.parent / "boefjes" / "plugins")
        runner = LocalNormalizerJobRunner(local_repository)
        output = runner.run(meta, get_dummy_data("tmp_large_nmap.xml"))

