package protocol

import (
	"regexp"
	"strings"
)

// Native SQL is a positive, whole-statement grammar, not a blacklist. Everything
// else requires a synthetic producer or a protocol-native rejection. In
// particular comments, functions, identifiers, parameters and compound statements
// cannot hide a privileged operation inside an apparently harmless SELECT.
var nativeConstant = regexp.MustCompile(`(?i)^select\s+(?:[0-9]{1,9}|null|true|false)(?:\s*,\s*(?:[0-9]{1,9}|null|true|false))*$`)
var nativeTransaction = regexp.MustCompile(`(?i)^(?:begin(?:\s+(?:work|transaction))?|start\s+transaction|commit(?:\s+work)?|rollback(?:\s+work)?|end(?:\s+work)?|abort(?:\s+work)?)$`)

func nativeSQLAllowed(sql string) bool {
	if len(sql) > 65536 {
		return false
	}
	sql = strings.TrimSpace(sql)
	sql = strings.TrimSpace(strings.TrimSuffix(sql, ";"))
	return nativeConstant.MatchString(sql) || nativeTransaction.MatchString(sql)
}
