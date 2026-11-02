"""Tests for report.py, run from this directory: python3 -m unittest test_report"""
import unittest

import report


class ReadWindowsTest(unittest.TestCase):
    def test_pairs_become_windows(self):
        marks = ["100.0 S a", "101.0 E a", "102.0 S b", "103.5 E b"]
        self.assertEqual(report.read_windows(marks), [(100.0, 101.0, "a"), (102.0, 103.5, "b")])

    def test_blank_and_short_lines_are_skipped(self):
        self.assertEqual(report.read_windows(["", "100.0 S", "100.0 S a", "101.0 E a"]), [(100.0, 101.0, "a")])

    def test_repeated_start(self):
        with self.assertRaisesRegex(SystemExit, "started twice"):
            report.read_windows(["100.0 S a", "101.0 S a"])

    def test_end_without_start(self):
        with self.assertRaisesRegex(SystemExit, "ended without a start"):
            report.read_windows(["100.0 E a"])

    def test_unclosed_window(self):
        with self.assertRaisesRegex(SystemExit, "has no end"):
            report.read_windows(["100.0 S a", "101.0 E a", "102.0 S b"])

    def test_unclosed_window_across_concatenated_files(self):
        first = ["100.0 S a"]
        second = ["200.0 S b", "201.0 E b"]
        with self.assertRaisesRegex(SystemExit, "has no end"):
            report.read_windows(first + second)

    def test_unknown_kind(self):
        for kind in ("START", "s", "e", "X"):
            with self.subTest(kind=kind), self.assertRaisesRegex(SystemExit, "unknown mark kind"):
                report.read_windows([f"100.0 {kind} a"])

    def test_invalid_timestamp(self):
        for stamp in ("soon", "nan", "inf", "-inf"):
            with self.subTest(stamp=stamp), self.assertRaisesRegex(SystemExit, "invalid mark timestamp"):
                report.read_windows([f"{stamp} S a"])


class WindowOfTest(unittest.TestCase):
    windows = [(100.0, 101.0, "a"), (101.3, 102.0, "b")]

    def test_inside_a_window(self):
        self.assertEqual(report.window_of(self.windows, 100.5), "a")
        self.assertEqual(report.window_of(self.windows, 101.5), "b")

    def test_inside_wins_over_padding_of_a_neighbour(self):
        # 101.35 is inside b and also within a's 0.5 s trailing padding.
        self.assertEqual(report.window_of(self.windows, 101.35), "b")

    def test_padding_picks_the_closest_window(self):
        # 101.1 is only in a's trailing padding.
        self.assertEqual(report.window_of(self.windows, 101.1), "a")
        # 101.27 is 0.27 after a and 0.03 before b, both within padding.
        self.assertEqual(report.window_of(self.windows, 101.27), "b")

    def test_padding_is_shorter_before_a_window(self):
        self.assertEqual(report.window_of(self.windows, 99.96), "a")
        self.assertEqual(report.window_of(self.windows, 99.9), "(outside-tests)")

    def test_outside(self):
        self.assertEqual(report.window_of(self.windows, 105.0), "(outside-tests)")
        self.assertEqual(report.window_of([], 100.0), "(outside-tests)")


if __name__ == "__main__":
    unittest.main()
