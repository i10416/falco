// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Substr_Name = "substr"

var Substr_ArgumentTypes = []value.Type{value.StringType, value.IntegerType, value.IntegerType}

func Substr_Validate(args []value.Value) error {
	if len(args) < 2 || len(args) > 3 {
		return errors.ArgumentNotInRange(Substr_Name, 2, 3, args)
	}
	for i := range args {
		if args[i].Type() != Substr_ArgumentTypes[i] {
			return errors.TypeMismatch(Substr_Name, i+1, Substr_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of substr
// Arguments may be:
// - STRING, INTEGER, INTEGER
// - STRING, INTEGER
// Reference: https://developer.fastly.com/reference/vcl/functions/strings/substr/
func Substr(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Substr_Validate(args); err != nil {
		return value.Null, err
	}

	input := value.Unwrap[*value.String](args[0]).Value
	offset := int(value.Unwrap[*value.Integer](args[1]).Value)
	var length *int
	if len(args) > 2 {
		v := int(value.Unwrap[*value.Integer](args[2]).Value)
		length = &v
	}

	var start, end int
	if offset < 0 {
		start = len(input) + offset
		if start < 0 {
			return &value.String{}, nil
		}
	} else {
		start = offset
	}
	if length == nil {
		end = len(input)
	} else if *length < 0 {
		end = len(input) + *length
	} else {
		end = start + *length
		// Handle integer overflow
		if end < 0 {
			return &value.String{}, nil
		}
	}
	if end > len(input) {
		end = len(input)
	}

	if start > len(input) {
		return &value.String{}, nil
	}
	if end <= start {
		return &value.String{}, nil
	}
	return &value.String{Value: input[start:end]}, nil
}
