// Code generated by __generator__/interpreter.go at once

package builtin

import (
	"net/textproto"
	"strings"

	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	flchttp "github.com/ysugimoto/falco/interpreter/http"
	"github.com/ysugimoto/falco/interpreter/value"
)

const Setcookie_delete_by_name_Name = "setcookie.delete_by_name"

var Setcookie_delete_by_name_ArgumentTypes = []value.Type{value.IdentType, value.StringType}

func Setcookie_delete_by_name_Validate(args []value.Value) error {
	if len(args) != 2 {
		return errors.ArgumentNotEnough(Setcookie_delete_by_name_Name, 2, args)
	}
	for i := range args {
		if args[i].Type() != Setcookie_delete_by_name_ArgumentTypes[i] {
			return errors.TypeMismatch(Setcookie_delete_by_name_Name, i+1, Setcookie_delete_by_name_ArgumentTypes[i], args[i].Type())
		}
	}
	return nil
}

// Fastly built-in function implementation of setcookie.delete_by_name
// Arguments may be:
// - ID, STRING
// Reference: https://developer.fastly.com/reference/vcl/functions/miscellaneous/setcookie-delete-by-name/
func Setcookie_delete_by_name(ctx *context.Context, args ...value.Value) (value.Value, error) {
	// Argument validations
	if err := Setcookie_delete_by_name_Validate(args); err != nil {
		return value.Null, err
	}

	where := value.Unwrap[*value.Ident](args[0])
	name := value.GetString(args[1]).String()

	var resp *flchttp.Response
	switch where.Value {
	case "beresp":
		if !ctx.Scope.Is(context.FetchScope) {
			return value.Null, errors.New(Setcookie_delete_by_name_Name, "beresp is not accessible in %s scope", ctx.Scope)
		}
		resp = ctx.BackendResponse
	case "resp":
		if !ctx.Scope.Is(context.DeliverScope, context.LogScope) {
			return value.Null, errors.New(Setcookie_delete_by_name_Name, "resp is not accessible in %s scope", ctx.Scope)
		}
		resp = ctx.Response
	default:
		return value.Null, errors.New(
			Setcookie_delete_by_name_Name, "Invalid ident: %s", where.Value,
		)
	}

	setCookies, ok := resp.Header[textproto.CanonicalMIMEHeaderKey("Set-Cookie")]
	if !ok {
		return &value.Boolean{Value: false}, nil
	}

	var isDeleted bool
	var filtered [][]flchttp.HeaderItem
	for _, sc := range setCookies {
		if !strings.HasPrefix(sc[0].Key.StrictString(), name+"=") {
			continue
		}
		filtered = append(filtered, sc)
		isDeleted = true
	}

	if !isDeleted {
		return &value.Boolean{Value: false}, nil
	}

	if len(filtered) == 0 {
		resp.Header.Del("Set-Cookie")
	} else {
		resp.Header[textproto.CanonicalMIMEHeaderKey("Set-Cookie")] = filtered
	}
	return &value.Boolean{Value: true}, nil
}
