package principal

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReservedAndSensitiveStatements(t *testing.T) {
	if !Reserved("fake_one") || !Reserved("FAKE_ONE") || Reserved("postgres") {
		t.Fatal("namespace")
	}
	for _, sql := range []string{"CREATE USER fake_one PASSWORD 'not-for-evidence'", "CREATE/**/ROLE fake_one LOGIN PASSWORD 'not-for-evidence'", "ALTER USER fake_one IDENTIFIED BY 'not-for-evidence'", "GRANT ALL ON *.* TO fake_one", "DO 'create user'", "/*!50000CREATE USER fake_x IDENTIFIED BY 'not-for-evidence' */", "CREATE /*!50000USER*/ fake_x IDENTIFIED BY 'not-for-evidence'", "PREPARE s FROM 'create user'"} {
		if !AccountSQL(sql) || strings.Contains(Redact(sql), "not-for-evidence") {
			t.Fatal("unredacted account statement")
		}
	}
	if AccountSQL("select password from employees") {
		t.Fatal("ordinary evidence query blocked")
	}
}
func TestRegistryTransportFailsClosed(t *testing.T) {
	t.Setenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", "")
	var result Reply
	if Call(context.Background(), "native-auth", nil, &result) == nil {
		t.Fatal("missing secret accepted")
	}
	t.Setenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32))))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Deceptive-Principal-Key") == "" {
			t.Error("missing internal auth")
		}
		w.WriteHeader(503)
		_, _ = w.Write([]byte("sensitive backend failure"))
	}))
	defer server.Close()
	t.Setenv("DECEPTION_ENGINE_URL", server.URL+"/decide")
	err := Call(context.Background(), "native-auth", nil, &result)
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("unsafe error")
	}
}
