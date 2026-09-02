package protocol

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestQualifiedDeceptionTableExtraction(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM testdb.employees WHERE id = 1",
		"UPDATE testdb.employees SET salary=1 WHERE id=1",
		"INSERT INTO testdb.employees (id) VALUES (1)",
	} {
		if got := extractDeceptionTableName(sql); got != "employees" {
			t.Fatalf("extractDeceptionTableName(%q)=%q", sql, got)
		}
	}
}

func TestDeceptionRowsPreserveNullAndFixedInteger(t *testing.T) {
	dec := &deceptionDecisionResponse{
		Columns:     []string{"manager_id", "base_salary"},
		ColumnTypes: []string{"integer", "integer"},
		Rows:        []map[string]interface{}{{"manager_id": nil, "base_salary": float64(1052359)}},
	}
	rows := decisionRowsAsMySQLBytes(dec)
	if rows[0][0] != nil {
		t.Fatal("SQL NULL was not preserved")
	}
	if got := string(rows[0][1]); got != "1052359" {
		t.Fatalf("fixed integer rendered as %q", got)
	}
	if got := formatDecisionValue(true, "boolean"); got != "1" {
		t.Fatalf("MySQL boolean text encoding=%q", got)
	}
}

func TestMutationDecisionWritesMySQLOK(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	h := &Handler{clientConn: server}
	done := make(chan error, 1)
	affected := 1
	go func() {
		done <- h.sendMySQLDeceptionResult(&deceptionDecisionResponse{
			Mode: "fake", AffectedRows: &affected,
		})
	}()
	header := make([]byte, 4)
	if _, err := client.Read(header); err != nil {
		t.Fatal(err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	payload := make([]byte, length)
	if _, err := client.Read(payload); err != nil {
		t.Fatal(err)
	}
	if payload[0] != packetOK || payload[1] != 1 {
		t.Fatalf("expected OK affected_rows=1, got %v", payload)
	}
	if status := binary.LittleEndian.Uint16(payload[3:5]); status != 2 {
		t.Fatalf("unexpected status flags %d", status)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
