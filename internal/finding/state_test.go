package finding

import "testing"

func TestTransitions(t *testing.T) {
	tests := []struct {
		from, to State
		want     bool
	}{
		{StateNew, StateInProgress, true},
		{StateInProgress, StateNotAffected, true},
		{StateNotAffected, StateInProgress, true},
		{StateNew, StateNew, false},
		{StateResolved, StateInProgress, false}, // only evidence can reopen
		{StateResolved, StateReopened, true},
		{StateNotAffected, StateResolved, false},
		{StateNew, StateReopened, false},
	}
	for _, tc := range tests {
		if got := CanTransition(tc.from, tc.to); got != tc.want {
			t.Errorf("%s -> %s = %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
	for from := range transitions {
		if CanTransition(from, from) {
			t.Errorf("%s may transition to itself", from)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if !(SeverityRank(SeverityCritical) < SeverityRank(SeverityHigh) &&
		SeverityRank(SeverityHigh) < SeverityRank(SeverityMedium) &&
		SeverityRank(SeverityLow) < SeverityRank(SeverityUnassigned)) {
		t.Fatal("severity ranks out of order")
	}
}
