package cmd

import (
	"testing"
	"time"
)

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	ok := map[string]time.Time{
		"90d": now.AddDate(0, 0, -90),
		"6w":  now.AddDate(0, 0, -42),
		"3m":  now.AddDate(0, -3, 0),
		"1y":  now.AddDate(-1, 0, 0),
		"2Y":  now.AddDate(-2, 0, 0), // case-insensitive
		"0d":  now,
	}
	for in, want := range ok {
		got, err := parseSince(in, now)
		if err != nil {
			t.Errorf("parseSince(%q) error: %v", in, err)
			continue
		}
		if !got.Equal(want) {
			t.Errorf("parseSince(%q) = %v, want %v", in, got, want)
		}
	}

	for _, bad := range []string{"", "y", "3", "3x", "-1m", "abc", "1.5y", "m3"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("parseSince(%q): expected error, got nil", bad)
		}
	}
}
