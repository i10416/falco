// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"strings"
	"testing"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

// Fastly built-in function testing implementation of randomstr
// Arguments may be:
// - INTEGER
// - INTEGER, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/randomness/randomstr/
func Test_Randomstr(t *testing.T) {
	tests := []struct {
		length     int64
		characters string
	}{
		{length: 10, characters: "1234567890abcdef"},
		{length: 5, characters: "abcdef"},
	}

	for i, tt := range tests {
		for j := 0; j < 10000; j++ {
			ret, err := Randomstr(
				&context.Context{},
				&value.Integer{Value: tt.length},
				&value.String{Value: tt.characters},
			)
			if err != nil {
				t.Errorf("[%d] Unexpected error: %s", i, err)
			}
			if ret.Type() != value.StringType {
				t.Errorf("[%d] Unexpected return type, expect=STRING, got=%s", i, ret.Type())
			}
			v := value.Unwrap[*value.String](ret)
			for _, s := range v.Value {
				if !strings.Contains(tt.characters, string(s)) {
					t.Errorf("[%d] Unexpected return value, character %s should be once of %s", i, string(s), tt.characters)
				}
			}
		}
	}
}
