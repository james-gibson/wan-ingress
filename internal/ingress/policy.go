package ingress

import (
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
)

// policyVersion names the derivation. A different canonical form must produce a
// different isotope, so the version travels inside the hashed material rather
// than beside it.
const policyVersion = "wan-ingress-policy-v1"

// PolicyIsotope derives one value from the agreement file: the same declaration
// yields the same isotope on every node, and any difference in what is declared
// yields a different one. It is not stored and not accepted from a caller —
// `LoadAgreements` is the only input, so a node can only ever report the
// declaration it is actually running.
//
// The point (lab/SPLASH.md, *Derived values*): no node stores the answer, every
// node can compute it, and a divergence is visible from outside the node that
// computed it. Comparing two `/policy` responses is that check.
func (r *Resolver) PolicyIsotope() string {
	sum := sha256.Sum256([]byte(r.canonicalPolicy()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// canonicalPolicy renders the declaration in a form that does not depend on
// JSON key order, agreement order or alias order — two files that declare the
// same routes must hash the same, or the comparison means nothing.
func (r *Resolver) canonicalPolicy() string {
	var b strings.Builder
	b.WriteString(policyVersion)
	b.WriteByte('\n')
	if r == nil {
		return b.String()
	}

	agreements := append([]Agreement(nil), r.agreements...)
	sort.Slice(agreements, func(i, j int) bool { return agreements[i].ID < agreements[j].ID })
	for _, a := range agreements {
		aliases := append([]string(nil), a.Aliases...)
		sort.Strings(aliases)
		b.WriteString(a.ID)
		b.WriteByte('\t')
		b.WriteString(a.Namespace)
		b.WriteByte('\t')
		b.WriteString(a.Border)
		b.WriteByte('\t')
		b.WriteString(strconv.Itoa(a.Rung))
		b.WriteByte('\t')
		b.WriteString(strings.Join(aliases, ","))
		b.WriteByte('\n')
	}
	return b.String()
}

// PolicySummary is the externally observable form: the derived value and the
// size of the declaration, never its contents. It is what one node shows
// another (or a monitor) to answer "do we agree?".
type PolicySummary struct {
	Isotope    string `json:"isotope"`
	Agreements int    `json:"agreements"`
	Aliases    int    `json:"aliases"`
}

// Summary derives the observable view of the route table.
func (r *Resolver) Summary() PolicySummary {
	summary := PolicySummary{Isotope: r.PolicyIsotope()}
	if r == nil {
		return summary
	}
	summary.Agreements = len(r.agreements)
	for _, a := range r.agreements {
		summary.Aliases += len(a.Aliases)
	}
	return summary
}
