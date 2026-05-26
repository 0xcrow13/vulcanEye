package scanner

import "strings"

func IsNumericParam(param string) bool {
	param = strings.ToLower(param)
	return strings.Contains(param, "id") || strings.Contains(param, "num") || strings.Contains(param, "age")
}

func mapToURLValues(m map[string][]string) map[string][]string {
	return m
}
