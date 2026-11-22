package export

import "testing"

func TestSafeRow(t *testing.T) {
	got := SafeRow([]string{"=HYPERLINK(\"x\")", "+cmd", "@SUM(1)", "-5", "Apache", ""})
	want := []string{"'=HYPERLINK(\"x\")", "'+cmd", "'@SUM(1)", "-5", "Apache", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %q != %q", i, got[i], want[i])
		}
	}
}
