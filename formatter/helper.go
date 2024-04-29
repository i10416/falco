package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/ast"
)

func isInlineComment(comments ast.Comments) bool {
	if len(comments) == 0 {
		return true
	}
	return strings.HasPrefix(comments[0].Value, "/*")
}

func getLineOffset(b bytes.Buffer) int {
	s := b.String()
	if p := strings.LastIndex(s, "\n"); p >= 0 {
		return len(s[p:])
	}
	return len(s)
}

func formatChunkedString(chunk string, indent string) string {
	var buf bytes.Buffer

	for _, line := range strings.Split(chunk, "\n") {
		buf.WriteString(indent + strings.TrimSpace(line) + "\n")
	}
	return buf.String()
}
