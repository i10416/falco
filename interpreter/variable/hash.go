package variable

import (
	"fmt"

	"net/netip"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/interpreter/value"
)

type HashScopeVariables struct {
	Variable
	base *AllScopeVariables
	ctx  *context.Context
}

func NewHashScopeVariables(ctx *context.Context) *HashScopeVariables {
	return &HashScopeVariables{
		base: NewAllScopeVariables(ctx),
		ctx:  ctx,
	}
}

func (v *HashScopeVariables) Get(s context.Scope, name string) (value.Value, error) {
	switch name {
	case REQ_HASH:
		return v.ctx.RequestHash, nil
	case REQ_IS_IPV6:
		parsed, err := netip.ParseAddr(v.ctx.Request.RemoteAddr)
		if err != nil {
			return value.Null, errors.WithStack(fmt.Errorf(
				"Could not parse remote address",
			))
		}
		return &value.Boolean{Value: parsed.Is6()}, nil

	case REQ_IS_PURGE:
		return &value.Boolean{Value: v.ctx.Request.Method == PURGE}, nil
	case FASTLY_INFO_REQUEST_ID:
		return v.ctx.RequestID, nil
	case FASTLY_DDOS_DETECTED:
		if v := lookupOverride(v.ctx, name); v != nil {
			return v, nil
		}
		return &value.Boolean{Value: false}, nil
	}

	// Look up shared variables
	if val, err := GetQuicVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetTLSVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}
	if val, err := GetFastlyInfoVariable(v.ctx, name); err != nil {
		return value.Null, errors.WithStack(err)
	} else if val != nil {
		return val, nil
	}

	// If not found, also look up all scope value
	val, err := v.base.Get(s, name)
	if err != nil {
		return value.Null, errors.WithStack(err)
	}
	return val, nil
}

func (v *HashScopeVariables) Set(s context.Scope, name, operator string, val value.Value) error {
	if name == "req.hash" {
		// Special string assignment - normally "+=" operator cannot use for STRING type,
		// But the exception case that "+=" operation can use for the "req.hash".
		// See: https://fiddle.fastly.dev/fiddle/0f3fc0aa
		if val.Type() == value.StringType && operator == "+=" {
			hash := value.Unwrap[*value.String](val)
			v.ctx.RequestHash.Value += hash.Value
			return nil
		}
		if err := doAssign(v.ctx.RequestHash, operator, val); err != nil {
			return errors.WithStack(err)
		}
		return nil
	}
	// If not found, pass to all scope value
	return v.base.Set(s, name, operator, val)
}

func (v *HashScopeVariables) Add(s context.Scope, name string, val value.Value) error {
	// Nothing values to be enable to add in HASH, pass to base
	return v.base.Add(s, name, val)
}

func (v *HashScopeVariables) Unset(s context.Scope, name string) error {
	// Nothing values to be enable to unset in HASH, pass to base
	return v.base.Unset(s, name)
}
