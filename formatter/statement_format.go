package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/ast"
)

func (f *Formatter) formatStatement(stmt ast.Statement) string {
	var buf bytes.Buffer

	if block, ok := stmt.(*ast.BlockStatement); ok {
		// need subtract 1 because LEFT_BRACE is unnested
		buf.WriteString(f.formatComment(block.Leading, "\n", block.Nest-1))
		buf.WriteString(f.indent(block.Nest - 1))
		buf.WriteString(f.formatBlockStatement(block))
		buf.WriteString(f.trailing(block.Trailing))
		return buf.String()
	}

	buf.WriteString(f.formatComment(stmt.GetMeta().Leading, "\n", stmt.GetMeta().Nest))
	buf.WriteString(f.indent(stmt.GetMeta().Nest))

	var formatted string
	trailingNode := stmt
	switch t := stmt.(type) {
	case *ast.ImportStatement:
		formatted = f.formatImportStatement(t)
	case *ast.IncludeStatement:
		formatted = f.formatIncludeStatement(t)
	case *ast.DeclareStatement:
		formatted = f.formatDeclareStatement(t)
	case *ast.SetStatement:
		formatted = f.formatSetStatement(t)
	case *ast.UnsetStatement:
		formatted = f.formatUnsetStatement(t)
	case *ast.RemoveStatement:
		formatted = f.formatRemoveStatement(t)
	case *ast.SwitchStatement:
		formatted = f.formatSwitchStatement(t)
	case *ast.RestartStatement:
		formatted = f.formatRestartStatement(t)
	case *ast.EsiStatement:
		formatted = f.formatEsiStatement(t)
	case *ast.AddStatement:
		formatted = f.formatAddStatement(t)
	case *ast.CallStatement:
		formatted = f.formatCallStatement(t)
	case *ast.ErrorStatement:
		formatted = f.formatErrorStatement(t)
	case *ast.LogStatement:
		formatted = f.formatLogStatement(t)
	case *ast.ReturnStatement:
		formatted = f.formatReturnStatement(t)
	case *ast.SyntheticStatement:
		formatted = f.formatSyntheticStatement(t)
	case *ast.SyntheticBase64Statement:
		formatted = f.formatSyntheticBase64Statement(t)
	case *ast.GotoStatement:
		formatted = f.formatGotoStatement(t)
	case *ast.GotoDestinationStatement:
		formatted = f.formatGotoDestinationStatement(t)
	case *ast.FunctionCallStatement:
		formatted = f.formatFunctionCallStatement(t)

	// On if statement, trailing comment node depends on its declarations
	case *ast.IfStatement:
		formatted = f.formatIfStatement(t)
		switch {
		case t.Alternative != nil:
			// When "else" statament exists, trailing comment will be on it
			trailingNode = t.Alternative
		case len(t.Another) > 0:
			// When one of "else if" statament exists, trailing comment will be on it
			trailingNode = t.Another[len(t.Another)-1]
		default:
			// Otherwise, trailing comment will be on consequence
			trailingNode = t.Consequence
		}
	}
	buf.WriteString(formatted)
	buf.WriteString(f.trailing(trailingNode.GetMeta().Trailing))

	return buf.String()
}

func (f *Formatter) formatImportStatement(stmt *ast.ImportStatement) string {
	var buf bytes.Buffer

	buf.WriteString("import ")
	buf.WriteString(stmt.Name.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatIncludeStatement(stmt *ast.IncludeStatement) string {
	var buf bytes.Buffer

	buf.WriteString("include ")
	buf.WriteString(stmt.Module.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatBlockStatement(stmt *ast.BlockStatement) string {
	var buf bytes.Buffer

	buf.WriteString("{\n")
	for i := range stmt.Statements {
		if i > 0 {
			buf.WriteString(f.lineFeed(stmt.Statements[i].GetMeta()))
		}
		buf.WriteString(f.formatStatement(stmt.Statements[i]))
		buf.WriteString("\n")
	}
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	// need subtract 1 because RIGHT_BRACE is unnested
	buf.WriteString(f.indent(stmt.Meta.Nest - 1))
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatDeclareStatement(stmt *ast.DeclareStatement) string {
	var buf bytes.Buffer

	buf.WriteString("declare ")
	if v := f.formatComment(stmt.Infix, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString("local " + stmt.Name.String())
	buf.WriteString(" " + stmt.ValueType.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSetStatement(stmt *ast.SetStatement) string {
	var buf bytes.Buffer

	buf.WriteString("set " + stmt.Ident.String())
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatUnsetStatement(stmt *ast.UnsetStatement) string {
	var buf bytes.Buffer

	buf.WriteString("unset " + stmt.Ident.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatRemoveStatement(stmt *ast.RemoveStatement) string {
	var buf bytes.Buffer

	buf.WriteString("remove " + stmt.Ident.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatIfStatement(stmt *ast.IfStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Keyword)
	if v := f.formatComment(stmt.Infix, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	buf.WriteString(" (")

	// Condition expression chunk should be printed with multi-line
	offset := buf.Len()
	chunk := f.formatExpression(stmt.Condition).ChunkedString(stmt.Nest, offset)
	if strings.Contains(chunk, "\n") {
		buf.WriteString("\n")
		buf.WriteString(formatChunkedString(chunk, f.indent(stmt.Nest+1)))
		buf.WriteString(f.indent(stmt.Nest) + ") ")
	} else {
		buf.WriteString(chunk + ") ")
	}

	if v := f.formatComment(stmt.Consequence.Leading, "", 0); v != "" {
		buf.WriteString(v + " ")
	}
	buf.WriteString(f.formatBlockStatement(stmt.Consequence))
	if v := f.formatComment(stmt.Consequence.Trailing, "", 0); v != "" {
		// If comment is inline , concat to the same line
		if isInlineComment(stmt.Consequence.Trailing) {
			buf.WriteString(" " + v)
		} else {
			// Otherwise, print to the new line
			buf.WriteString("\n")
			buf.WriteString(f.indent(stmt.Consequence.Nest-1) + v)
			buf.WriteString("\n")
		}
	}
	for _, a := range stmt.Another {
		// If leading comments exists, keyword should be placed with line-feed
		if len(a.Leading) > 0 {
			buf.WriteString("\n")
			buf.WriteString(f.formatComment(a.Leading, "\n", a.Nest))
			buf.WriteString(f.indent(a.Nest))
		} else {
			// Otherwise, write one whitespace characeter
			buf.WriteString(" ")
		}
		// buf.WriteString(f.formatElseIfStatement(a))
		keyword := a.Keyword
		if f.conf.ElseIf {
			keyword = "else if"
		}
		buf.WriteString(keyword)
		if v := f.formatComment(a.Infix, "", 0); v != "" {
			buf.WriteString(" " + v)
		}
		buf.WriteString(" (")
		chunk := f.formatExpression(a.Condition).ChunkedString(a.Nest, getLineOffset(buf))
		if strings.Contains(chunk, "\n") {
			buf.WriteString("\n")
			buf.WriteString(formatChunkedString(chunk, f.indent(a.Nest+1)))
			buf.WriteString(f.indent(a.Nest) + ") ")
		} else {
			buf.WriteString(chunk + ") ")
		}
		if v := f.formatComment(a.Consequence.Leading, "", 0); v != "" {
			buf.WriteString(v + " ")
		}
		buf.WriteString(f.formatBlockStatement(a.Consequence))
		if v := f.formatComment(a.Consequence.Trailing, "", 0); v != "" {
			// If comment is inline , concat to the same line
			if isInlineComment(a.Consequence.Trailing) {
				buf.WriteString(" " + v)
			} else {
				// Otherwise, print to the new line
				buf.WriteString("\n")
				buf.WriteString(f.indent(a.Consequence.Nest-1) + v)
				buf.WriteString("\n")
			}
		}
	}
	if stmt.Alternative != nil {
		if len(stmt.Alternative.Leading) > 0 {
			buf.WriteString("\n")
			buf.WriteString(f.formatComment(stmt.Alternative.Leading, "\n", stmt.Alternative.Nest))
			buf.WriteString(f.indent(stmt.Alternative.Nest))
		} else {
			buf.WriteString(" ")
		}
		buf.WriteString("else ")
		if v := f.formatComment(stmt.Alternative.Infix, "", 0); v != "" {
			buf.WriteString(v + " ")
		}
		buf.WriteString(f.formatBlockStatement(stmt.Alternative.Consequence))
		buf.WriteString(f.trailing(stmt.Alternative.Consequence.Trailing))
	}

	return buf.String()
}

func (f *Formatter) formatSwitchStatement(stmt *ast.SwitchStatement) string {
	var buf bytes.Buffer

	buf.WriteString("switch (" + f.formatExpression(stmt.Control.Expression).String() + ") {\n")
	for _, c := range stmt.Cases {
		buf.WriteString(f.formatComment(c.Leading, "\n", c.Meta.Nest))
		buf.WriteString(f.indent(c.Meta.Nest))
		if c.Test != nil {
			buf.WriteString("case ")
			if c.Test.Operator == "~" {
				buf.WriteString("~ ")
			}
			buf.WriteString(f.formatExpression(c.Test.Right).String())
			buf.WriteString(":\n")
		} else {
			buf.WriteString("default:\n")
		}
		for _, s := range c.Statements {
			if _, ok := s.(*ast.BreakStatement); ok {
				buf.WriteString(f.indent(c.Meta.Nest + 1))
				buf.WriteString("break;")
			} else {
				buf.WriteString(f.formatStatement(s))
			}
			buf.WriteString("\n")
		}
		if c.Fallthrough {
			buf.WriteString(f.indent(c.Meta.Nest + 1))
			buf.WriteString("fallthrough;\n")
		}
	}
	if len(stmt.Infix) > 0 {
		buf.WriteString(f.formatComment(stmt.Infix, "\n", stmt.Meta.Nest))
	}
	buf.WriteString(f.indent(stmt.Meta.Nest))
	buf.WriteString("}")

	return buf.String()
}

func (f *Formatter) formatRestartStatement(stmt *ast.RestartStatement) string {
	var buf bytes.Buffer

	buf.WriteString("restart")
	if v := f.formatComment(stmt.Infix, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatEsiStatement(stmt *ast.EsiStatement) string {
	var buf bytes.Buffer

	buf.WriteString("esi")
	if v := f.formatComment(stmt.Infix, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatAddStatement(stmt *ast.AddStatement) string {
	var buf bytes.Buffer

	buf.WriteString("add " + stmt.Ident.String())
	buf.WriteString(" " + stmt.Operator.Operator + " ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatCallStatement(stmt *ast.CallStatement) string {
	var buf bytes.Buffer

	buf.WriteString("call " + stmt.Subroutine.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatErrorStatement(stmt *ast.ErrorStatement) string {
	var buf bytes.Buffer

	buf.WriteString("error " + stmt.Code.String())
	if stmt.Argument != nil {
		buf.WriteString(" " + stmt.Argument.String())
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatLogStatement(stmt *ast.LogStatement) string {
	var buf bytes.Buffer

	buf.WriteString("log ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatReturnStatement(stmt *ast.ReturnStatement) string {
	var buf bytes.Buffer

	buf.WriteString("return")
	if stmt.ReturnExpression != nil {
		if v := f.formatComment(stmt.ParenthesisLeadingComments, "", 0); v != "" {
			buf.WriteString(" " + v)
		}
		prefix := " "
		suffix := ""
		if f.conf.ReturnStatementParenthesis {
			prefix = " ("
			suffix = ")"
		}
		buf.WriteString(prefix)
		buf.WriteString(stmt.ReturnExpression.String())
		buf.WriteString(suffix)
		if v := f.formatComment(stmt.ParenthesisTrailingComments, "", 0); v != "" {
			buf.WriteString(" " + v)
		}
	} else {
		if v := f.formatComment(stmt.Infix, "", 0); v != "" {
			buf.WriteString(" " + v)
		}
	}
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSyntheticStatement(stmt *ast.SyntheticStatement) string {
	var buf bytes.Buffer

	buf.WriteString("synthetic ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatSyntheticBase64Statement(stmt *ast.SyntheticBase64Statement) string {
	var buf bytes.Buffer

	buf.WriteString("synthetic.base64 ")
	buf.WriteString(f.formatExpression(stmt.Value).ChunkedString(stmt.Nest, buf.Len()))
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatGotoStatement(stmt *ast.GotoStatement) string {
	var buf bytes.Buffer

	buf.WriteString("goto " + stmt.Destination.String())
	buf.WriteString(";")

	return buf.String()
}

func (f *Formatter) formatGotoDestinationStatement(stmt *ast.GotoDestinationStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Name.Value)

	return buf.String()
}

func (f *Formatter) formatFunctionCallStatement(stmt *ast.FunctionCallStatement) string {
	var buf bytes.Buffer

	buf.WriteString(stmt.Function.Value + "(")
	length := buf.Len()
	for i, a := range stmt.Arguments {
		buf.WriteString(f.formatExpression(a).ChunkedString(stmt.Nest, length))
		if i != len(stmt.Arguments)-1 {
			buf.WriteString(", ")
		}
	}
	buf.WriteString(")")
	if v := f.formatComment(stmt.Infix, "", 0); v != "" {
		buf.WriteString(" " + v)
	}
	buf.WriteString(";")

	return buf.String()
}
