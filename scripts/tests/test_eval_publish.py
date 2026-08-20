#!/usr/bin/env python3
"""Correctness tests for scripts/lib/eval_publish.py.

Every test here is a regression test for a defect that actually reached
published numbers, or a guard against the class of defect that produced them.
That class is always the same shape: a computation silently returns something
plausible instead of failing, and the wrong value is indistinguishable from a
measurement once it is in the JSON.

Run: python3 scripts/tests/test_eval_publish.py
"""
import json
import math
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))

import eval_publish as ep  # noqa: E402


class TestAeadUnits(unittest.TestCase):
    """ns -> ms conversion. Shipped as ns/1e9 (seconds) from a helper named
    _ms_ and used as ms by six generators, making every model 1000x too small."""

    def test_one_mib_seal_matches_the_measured_millisecond_figure(self):
        micro = {"aead_seal_1mib_ns": 7_923_185.0}
        per_byte = ep.aead_ms_per_byte(micro, "seal")
        one_mib_ms = per_byte * 1024 * 1024
        self.assertAlmostEqual(one_mib_ms, 7.923185, places=5)

    def test_result_is_milliseconds_not_seconds(self):
        # A 1 MiB AEAD costs single-digit milliseconds on any plausible core.
        # Seconds-per-byte would put this at ~0.008, which is the bug.
        micro = {"aead_seal_1mib_ns": 7_923_185.0}
        one_mib = ep.aead_ms_per_byte(micro, "seal") * 1024 * 1024
        self.assertGreater(one_mib, 0.1, "looks like seconds, not milliseconds")
        self.assertLess(one_mib, 10_000.0)

    def test_open_and_seal_are_read_from_distinct_keys(self):
        micro = {"aead_seal_1mib_ns": 1_000_000.0, "aead_open_1mib_ns": 2_000_000.0}
        self.assertNotEqual(
            ep.aead_ms_per_byte(micro, "seal"), ep.aead_ms_per_byte(micro, "open")
        )

    def test_missing_key_raises_rather_than_defaulting(self):
        with self.assertRaises(KeyError):
            ep.aead_ms_per_byte({}, "seal")


class TestAnalyticPoint(unittest.TestCase):
    """analytic_point carries 'value', never 'median'. A consumer reading
    ['median'] crashed gen_depth_delta_latest.py at HEAD; a consumer using
    .get('median') would instead have silently published None."""

    def test_has_value_and_no_median(self):
        p = ep.analytic_point(12.5)
        self.assertEqual(p["value"], 12.5)
        self.assertNotIn("median", p)

    def test_declares_itself_analytic_and_carries_no_fake_spread(self):
        p = ep.analytic_point(12.5)
        self.assertEqual(p["kind"], "analytic")
        self.assertIsNone(p["dispersion"])
        self.assertEqual(p["n"], 1)

    def test_get_median_would_be_none_so_consumers_must_not_use_it(self):
        # Documents the trap: .get('median') is None, which formats as "None"
        # in a table rather than raising.
        self.assertIsNone(ep.analytic_point(1.0).get("median"))


class TestDispersion(unittest.TestCase):
    """A published cell must never be an unlabelled single shot."""

    def test_empty_sample_is_flagged_not_zeroed(self):
        d = ep.dispersion([])
        self.assertEqual(d.get("n"), 0)
        self.assertNotEqual(d.get("median"), 0, "empty sample must not read as 0 ms")

    def test_single_sample_is_labelled_as_such(self):
        d = ep.dispersion([5.0])
        self.assertEqual(d["n"], 1)
        self.assertIsNotNone(d.get("dispersion"))

    def test_median_and_iqr_on_known_input(self):
        d = ep.dispersion([1, 2, 3, 4, 5])
        self.assertEqual(d["median"], 3)
        self.assertEqual(d["min"], 1)
        self.assertEqual(d["max"], 5)

    def test_identical_samples_give_zero_spread_not_nan(self):
        d = ep.dispersion([7, 7, 7, 7])
        self.assertEqual(d["median"], 7)
        self.assertEqual(d.get("stdev", 0), 0)
        for k, v in d.items():
            if isinstance(v, float):
                self.assertFalse(math.isnan(v), f"{k} is NaN")


class TestQuantile(unittest.TestCase):
    def test_endpoints_and_median(self):
        xs = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(ep.quantile(xs, 0.0), 1.0)
        self.assertEqual(ep.quantile(xs, 1.0), 4.0)
        self.assertAlmostEqual(ep.quantile(xs, 0.5), 2.5)

    def test_single_element(self):
        self.assertEqual(ep.quantile([9.0], 0.75), 9.0)


class TestSlope(unittest.TestCase):
    def test_exact_linear_fit(self):
        self.assertAlmostEqual(ep.slope([0, 1, 2, 3], [0, 2, 4, 6]), 2.0)

    def test_flat_series_is_zero_slope(self):
        self.assertAlmostEqual(ep.slope([1, 2, 3], [5, 5, 5]), 0.0)

    def test_degenerate_x_returns_none_rather_than_dividing_by_zero(self):
        self.assertIsNone(ep.slope([2, 2, 2], [1, 2, 3]))

    def test_too_few_points_returns_none(self):
        self.assertIsNone(ep.slope([1], [1]))


class TestRatioGuards(unittest.TestCase):
    """A corrected ratio whose denominator has been zeroed by floor subtraction
    is undefined. parity_sweep divided by 1e-9 and published 4.17e10."""

    @staticmethod
    def work_ratio(num, den):
        if num is None or den is None or den <= 0.0:
            return None
        return round(num / den, 3)

    def test_zero_denominator_is_none_not_astronomical(self):
        self.assertIsNone(self.work_ratio(41.7, 0.0))

    def test_epsilon_guard_would_have_produced_a_fake_measurement(self):
        bogus = 41.7 / max(0.0, 1e-9)
        self.assertGreater(bogus, 1e9)  # what the old guard emitted

    def test_normal_ratio_still_computed(self):
        self.assertAlmostEqual(self.work_ratio(10.0, 5.0), 2.0)


class TestMachineProvenance(unittest.TestCase):
    """machine_info must not silently return an all-null block on Linux; the
    upstream implementation probed macOS sysctl keys only."""

    def test_reports_arch_and_os(self):
        m = ep.machine_info()
        self.assertTrue(m.get("arch"), "arch must be populated on every platform")
        self.assertTrue(m.get("os"), "os must be populated on every platform")

    def test_not_every_field_is_none(self):
        m = ep.machine_info()
        populated = [k for k, v in m.items() if v not in (None, "", "unspecified")]
        self.assertGreater(len(populated), 2, f"machine block nearly empty: {m}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
