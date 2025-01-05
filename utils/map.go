package utils

import "github.com/arqut/common/types"

func MapVal(m types.Map, key string, def ...interface{}) interface{} {
	val, ok := m[key]
	if !ok {
		if len(def) > 0 {
			return def[0]
		}
		return nil
	}
	return val
}

func MapIntVal(m types.Map, key string, def ...int) int {
	return MapVal(m, key, def).(int)
}

func MapStringVal(m types.Map, key string, def ...string) string {
	return MapVal(m, key, def).(string)
}
