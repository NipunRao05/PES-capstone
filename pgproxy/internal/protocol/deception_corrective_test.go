package protocol

import "testing"

func TestDeceptionRowsPreserveNullAndFixedInteger(t *testing.T) {
	dec := &deceptionDecisionResponse{
		Columns:     []string{"manager_id", "base_salary"},
		ColumnTypes: []string{"integer", "integer"},
		Rows:        []map[string]interface{}{{"manager_id": nil, "base_salary": float64(1052359)}},
	}
	rows := decisionRowsAsBytes(dec)
	if rows[0][0] != nil {
		t.Fatal("SQL NULL was not preserved")
	}
	if got := string(rows[0][1]); got != "1052359" {
		t.Fatalf("fixed integer rendered as %q", got)
	}
}

func TestPostgresTypeMetadata(t *testing.T) {
	tests := map[string]uint32{
		"integer": 23, "bigint": 20, "numeric": 1700,
		"boolean": 16, "date": 1082, "timestamp without time zone": 1114,
	}
	for name, expected := range tests {
		oid, _ := postgresTypeMetadata(name)
		if oid != expected {
			t.Fatalf("postgresTypeMetadata(%q)=%d, want %d", name, oid, expected)
		}
	}
	if got := formatDecisionValue(true, "boolean"); got != "t" {
		t.Fatalf("PostgreSQL boolean text encoding=%q", got)
	}
}
