package protocol

import "testing"

func TestNativePositiveGrammar(t *testing.T) {
	for _, sql := range []string{"SELECT 1;", "select 12, null, true", "BEGIN", "START TRANSACTION", "COMMIT", "ROLLBACK", "END", "ABORT"} {
		if !nativeSQLAllowed(sql) {
			t.Errorf("benign statement rejected: %q", sql)
		}
	}
	for _, sql := range []string{
		"CREATE ROLE unsafe LOGIN", "ALTER ROLE postgres SUPERUSER", "CREATE DATABASE unsafe",
		"COPY t TO PROGRAM 'never-executed'", "SELECT pg_read_file('never-read')", "SELECT pg_write_file('never-written','x')",
		"SELECT pg_ls_dir('.')", "SELECT lo_import('never-read')", "SELECT lo_export(1,'never-written')",
		"CREATE EXTENSION unsafe", "ALTER SYSTEM SET x='y'", "SET ROLE postgres", "SELECT current_user",
		"SELECT 1; DROP DATABASE testdb", "SELECT 1 /* comment */", "SELECT $$;select pg_read_file('x')$$",
		"SELECT 1 --comment", "SELECT 1 INTO OUTFILE 'never-written'", "LOAD DATA LOCAL INFILE 'never-read'",
		"/*!50000 SET GLOBAL x=1 */", "GRANT ALL ON *.* TO x", "INSTALL PLUGIN x SONAME 'x'",
		"SHUTDOWN", "SET GLOBAL x=1", "SELECT LOAD_FILE('never-read')", "CALL unsafe()", "DO unsafe()",
		"SELECT (1)", "SELECT $1", "WITH x AS (DELETE FROM t) SELECT 1", "SELECT 1\x00",
	} {
		if nativeSQLAllowed(sql) {
			t.Errorf("unsafe or unsupported native statement accepted: %q", sql)
		}
	}
}

func TestNativeDeniedNeverReachesBackend(t *testing.T) {
	f := newErrorStateFixture(t)
	for _, sql := range []string{"SELECT pg_read_file('never-read')", "COPY t TO PROGRAM 'never-executed'", "CREATE EXTENSION unsafe", "SELECT 1; SELECT 2", "UPDATE physical SET id=1"} {
		f.query(t, sql, 'I', "42501", "")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forwarded) != 0 {
		t.Fatalf("rejected SQL reached backend: %v", f.forwarded)
	}
}
