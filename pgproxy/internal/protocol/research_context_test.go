package protocol

import (
	"github.com/pgproxy/internal/principal"
	"github.com/pgproxy/internal/session"
	"testing"
)

func TestOriginOwnedByListener(t *testing.T) {
	t.Setenv("RESEARCH_MANIFEST_ID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	h := &Handler{}
	if h.evidenceContext().TrafficOrigin != "unknown" {
		t.Fatal("unmarked handler must remain unknown")
	}
	h.sess = &session.Session{Context: principal.Context{TrafficOrigin: "operator_validation", DeploymentManifestID: "spoof"}}
	h.SetTrafficOrigin("research_external")
	if h.evidenceContext().TrafficOrigin != "research_external" {
		t.Fatal("public listener origin")
	}
	h.SetTrafficOrigin("operator_validation")
	c := h.evidenceContext()
	if c.TrafficOrigin != "operator_validation" || len(c.DeploymentManifestID) != 64 {
		t.Fatal("private listener metadata")
	}
	h.SetTrafficOrigin("application_name=operator_validation")
	if h.evidenceContext().TrafficOrigin != "unknown" {
		t.Fatal("attacker text accepted as origin")
	}
}
