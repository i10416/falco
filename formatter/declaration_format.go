package formatter

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatAclDeclaration(decl *ast.AclDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("acl ")
	buf.WriteString(decl.Name.String())
	buf.WriteString(" {\n")
	for i, cidr := range decl.CIDRs {
		if i > 0 {
			buf.WriteString(f.lineFeed(cidr.GetMeta()))
		}
		buf.WriteString(f.formatComment(cidr.Leading, "\n", 1))
		buf.WriteString(f.indent(1))
		if cidr.Inverse != nil && cidr.Inverse.Value {
			buf.WriteString("!")
		}
		if v := f.formatComment(cidr.IP.Leading, " ", 0); v != "" {
			buf.WriteString(" " + v + " ")
		}
		buf.WriteString(`"` + cidr.IP.Value + `"`)
		if cidr.Mask != nil {
			buf.WriteString("/" + cidr.Mask.String())
		}
		if v := f.formatComment(cidr.IP.Trailing, " ", 0); v != "" {
			buf.WriteString(" " + v)
		}
		buf.WriteString(";")
		buf.WriteString(f.trailing(cidr.Trailing))
		buf.WriteString("\n")
	}
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatBackendDeclaration(decl *ast.BackendDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("backend " + decl.Name.String() + " {\n")
	buf.WriteString(f.formatBackendProperties(decl.Properties, 1))
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatBackendProperties(props []*ast.BackendProperty, nestLevel int) string {
	var buf bytes.Buffer
	var maxPropLength int

	if f.conf.SortDeclarationProperty {
		sort.Slice(props, func(i, j int) bool {
			if props[i].Key.String() == "probe" {
				return false
			}
			return props[i].Key.String() < props[j].Key.String()
		})
	}

	for i := range props {
		if len(props[i].Key.String()) > maxPropLength {
			maxPropLength = len(props[i].Key.String())
		}
	}

	for i, prop := range props {
		if i > 0 {
			buf.WriteString(f.lineFeed(prop.GetMeta()))
		}
		buf.WriteString(f.formatComment(prop.Leading, "\n", nestLevel))
		buf.WriteString(f.indent(nestLevel))
		var left string
		if f.conf.AlignDeclarationProperty {
			format := fmt.Sprintf("%%-%ds", maxPropLength)
			left = fmt.Sprintf("."+format+" = ", prop.Key.String())
		} else {
			left = fmt.Sprintf(".%s = ", prop.Key.String())
		}
		buf.WriteString(left)
		if po, ok := prop.Value.(*ast.BackendProbeObject); ok {
			buf.WriteString("{\n")
			buf.WriteString(f.formatBackendProperties(po.Values, nestLevel+1))
			buf.WriteString(f.indent(nestLevel) + "}")
		} else {
			buf.WriteString(f.formatExpression(prop.Value).ChunkedString(prop.Nest, len(left)))
			buf.WriteString(";")
		}
		buf.WriteString(f.trailing(prop.Trailing))
		buf.WriteString("\n")
	}
	return buf.String()
}

func (f *Formatter) formatDirectorDeclaration(decl *ast.DirectorDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("director " + decl.Name.String() + " " + decl.DirectorType.String() + " {\n")
	for i, prop := range decl.Properties {
		if i > 0 {
			buf.WriteString(f.lineFeed(prop.GetMeta()))
		}
		buf.WriteString(f.formatComment(prop.GetMeta().Leading, "\n", 1))
		buf.WriteString(f.indent(1))
		switch t := prop.(type) {
		case *ast.DirectorBackendObject:
			buf.WriteString(f.formatDirectorBackend(t))
		case *ast.DirectorProperty:
			buf.WriteString(fmt.Sprintf(".%s = %s;", t.Key.String(), t.Value.String()))
		}
		buf.WriteString(f.trailing(prop.GetMeta().Trailing))
		buf.WriteString("\n")
	}
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatDirectorBackend(prop *ast.DirectorBackendObject) string {
	var buf bytes.Buffer

	if f.conf.SortDeclarationProperty {
		sort.Slice(prop.Values, func(i, j int) bool {
			return prop.Values[i].Key.String() < prop.Values[j].Key.String()
		})
	}

	buf.WriteString("{ ")
	for i, v := range prop.Values {
		if i > 0 {
			buf.WriteString(f.lineFeed(prop.GetMeta()))
		}
		if c := f.formatComment(v.Leading, "", 0); c != "" {
			buf.WriteString(c + " ")
		}
		buf.WriteString(fmt.Sprintf(".%s = %s; ", v.Key.String(), v.Value.String()))
	}
	if len(prop.Infix) > 0 {
		buf.WriteString(f.formatComment(prop.Infix, "", 0))
		buf.WriteString(" ")
	}
	buf.WriteString("}")
	buf.WriteString(f.trailing(prop.Trailing))

	return buf.String()
}

func (f *Formatter) formatTableDeclaration(decl *ast.TableDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("table " + decl.Name.String())
	if decl.ValueType != nil {
		buf.WriteString(" " + decl.ValueType.String())
	}
	buf.WriteString(" {\n")
	buf.WriteString(f.formatTableProperties(decl.Properties))
	if len(decl.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatTableProperties(props []*ast.TableProperty) string {
	var buf bytes.Buffer
	var maxPropLength int

	if f.conf.SortDeclarationProperty {
		sort.Slice(props, func(i, j int) bool {
			return props[i].Key.Value < props[j].Key.Value
		})
	}

	for i := range props {
		if len(props[i].Key.String()) > maxPropLength {
			maxPropLength = len(props[i].Key.String())
		}
	}

	for i, prop := range props {
		if i > 0 {
			buf.WriteString(f.lineFeed(prop.Meta))
		}
		buf.WriteString(f.formatComment(prop.Leading, "\n", 1))
		buf.WriteString(f.indent(1))
		if f.conf.AlignDeclarationProperty {
			format := fmt.Sprintf("%%-%ds", maxPropLength)
			buf.WriteString(fmt.Sprintf(format+": ", prop.Key.String()))
		} else {
			buf.WriteString(fmt.Sprintf("%s: ", prop.Key.String()))
		}
		buf.WriteString(prop.Value.String())
		buf.WriteString(",")
		buf.WriteString(f.trailing(prop.Trailing))
		buf.WriteString("\n")
	}

	return buf.String()
}

func (f *Formatter) formatPenaltyboxDeclaration(decl *ast.PenaltyboxDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("penaltybox " + decl.Name.String())
	buf.WriteString(" {\n")
	// penaltybox does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatRatecounterDeclaration(decl *ast.RatecounterDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("ratecounter " + decl.Name.String())
	buf.WriteString(" {\n")
	// ratecounter does not have properties
	if len(decl.Block.Infix) > 0 {
		buf.WriteString(f.indent(1))
		buf.WriteString(f.formatComment(decl.Block.Infix, "\n", 0))
	}
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatSubroutineDeclaration(decl *ast.SubroutineDeclaration) string {
	var buf bytes.Buffer

	buf.WriteString("sub " + decl.Name.String() + " ")
	if decl.ReturnType != nil {
		buf.WriteString(decl.ReturnType.String() + " ")
	}
	buf.WriteString(f.formatBlockStatement(decl.Block))

	return buf.String()
}
