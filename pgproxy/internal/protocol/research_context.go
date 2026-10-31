package protocol

import (
	"github.com/pgproxy/internal/principal"
	"os"
)

// Called by the listener owner only. SQL, application_name and login names cannot
// select origin. Historical/direct handler fixtures default to unknown.
func (h *Handler) SetTrafficOrigin(origin string) {
	if origin != "research_external" && origin != "operator_validation" {
		origin = "unknown"
	}
	h.trafficOrigin = origin
}
func (h *Handler) evidenceContext() principal.Context {
	var c principal.Context
	if h.sess != nil {
		c = h.sess.Context
	}
	c.TrafficOrigin = h.trafficOrigin
	if c.TrafficOrigin == "" {
		c.TrafficOrigin = "unknown"
	}
	c.DeploymentManifestID = os.Getenv("RESEARCH_MANIFEST_ID")
	return c
}
