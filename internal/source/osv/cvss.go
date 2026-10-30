package osv

import (
	"errors"
	"math"
	"strings"
)

// CVSS3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" (FIRST
// specification, section 7.1). Temporal and environmental metrics are
// ignored.
func CVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, errors.New("cvss: not a CVSS v3 vector")
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(p, ":"); ok {
			m[k] = v
		}
	}
	weight := func(metric string, table map[string]float64) (float64, bool) {
		w, ok := table[m[metric]]
		return w, ok
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, errors.New("cvss: missing scope")
	}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	av, ok1 := weight("AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac, ok2 := weight("AC", map[string]float64{"L": 0.77, "H": 0.44})
	prw, ok3 := weight("PR", pr)
	ui, ok4 := weight("UI", map[string]float64{"N": 0.85, "R": 0.62})
	c, ok5 := weight("C", cia)
	i, ok6 := weight("I", cia)
	a, ok7 := weight("A", cia)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, errors.New("cvss: missing base metric")
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	exploitability := 8.22 * av * ac * prw * ui
	if impact <= 0 {
		return 0, nil
	}
	if scope == "U" {
		return roundUp(math.Min(impact+exploitability, 10)), nil
	}
	return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
}

// roundUp is the specification's Roundup: the smallest one-decimal number
// equal to or higher than x, robust to floating point error.
func roundUp(x float64) float64 {
	i := math.Round(x * 100000)
	if math.Mod(i, 10000) == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}
