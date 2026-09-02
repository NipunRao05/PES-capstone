package protocol

import "testing"

func TestDeceptionCRUDRecognitionAndQualifiedIdentifiers(t *testing.T) {
	tests := []struct {
		sql   string
		table string
	}{
		{"select * from employees where id = 1", "employees"},
		{"select * from public.employees where id = 1", "employees"},
		{"update employees set salary = salary + 100 where id = 1", "employees"},
		{"update public.employees set salary = salary + 100 where id = 1", "employees"},
		{"insert into public.employees (id) values (1)", "employees"},
		{"delete from public.employees where id = 1", "employees"},
	}

	for _, test := range tests {
		if !shouldConsultDeceptionEngine(test.sql) {
			t.Errorf("expected deception consultation for %q", test.sql)
		}
		if got := extractDeceptionTableName(test.sql); got != test.table {
			t.Errorf("extractDeceptionTableName(%q)=%q, want %q", test.sql, got, test.table)
		}
	}
}

func TestPostgresMutationCommandTagsUseAffectedRows(t *testing.T) {
	for _, test := range []struct {
		sql  string
		want string
	}{
		{"update public.employees set salary = salary + 100 where id = 1", "UPDATE 1"},
		{"delete from public.employees where id = 1", "DELETE 1"},
		{"insert into public.employees (id) values (1)", "INSERT 0 1"},
	} {
		if got := string(postgresFakeCommandTag(test.sql, 0, 1)); got != test.want {
			t.Errorf("postgresFakeCommandTag(%q)=%q, want %q", test.sql, got, test.want)
		}
	}
}

func TestTransactionActionClassification(t *testing.T) {
	for sql, want := range map[string]string{
		"COMMIT":    "commit",
		"rollback;": "rollback",
		"select 1":  "",
	} {
		if got := deceptionTransactionAction(sql); got != want {
			t.Errorf("deceptionTransactionAction(%q)=%q, want %q", sql, got, want)
		}
	}
}

func TestFailedTransactionRejectsOnlyDeceptiveQueries(t *testing.T) {
	if !shouldRejectDeceptionQuery('E', "select * from public.employees where id = 1") {
		t.Fatal("deceptive SELECT must be rejected in a failed transaction")
	}
	if shouldRejectDeceptionQuery('T', "select * from public.employees where id = 1") {
		t.Fatal("active transaction must allow deceptive SELECT")
	}
	if shouldRejectDeceptionQuery('E', "rollback") {
		t.Fatal("ROLLBACK must reach PostgreSQL to clear failed transaction state")
	}
}
