package finding

// transitions lists, for each state, the states it may move to. Keeping
// the whole lifecycle in one table makes it reviewable and testable.
//
// Resolution (-> resolved) and regression (resolved -> reopened) are driven
// by evidence such as rescans; human decisions move findings between the
// triage states.
var transitions = map[State][]State{
	StateNeedsReview:          {StateNew, StateInProgress, StateAwaitingVerification, StateNotAffected, StateRiskAccepted, StateResolved},
	StateNew:                  {StateInProgress, StateAwaitingVerification, StateNotAffected, StateRiskAccepted, StateResolved},
	StateInProgress:           {StateNew, StateAwaitingVerification, StateNotAffected, StateRiskAccepted, StateResolved},
	StateAwaitingVerification: {StateNew, StateInProgress, StateNotAffected, StateRiskAccepted, StateResolved},
	StateNotAffected:          {StateNew, StateInProgress, StateRiskAccepted},
	StateRiskAccepted:         {StateNew, StateInProgress, StateNotAffected},
	StateResolved:             {StateReopened},
	StateReopened:             {StateNew, StateInProgress, StateAwaitingVerification, StateNotAffected, StateRiskAccepted, StateResolved},
}

// CanTransition reports whether a finding may move from one state to another.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Open reports whether the state still needs action.
func (s State) Open() bool {
	switch s {
	case StateResolved, StateNotAffected, StateRiskAccepted:
		return false
	}
	return true
}

// SeverityRank orders severities: 0 is most severe.
func SeverityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	}
	return 5
}
