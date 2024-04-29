package formatter

import (
	"bytes"
	"strings"

	"github.com/ysugimoto/falco/config"
)

type ChunkBuffer struct {
	chunks []string
	conf   *config.FormatConfig
}

func newBuffer(c *config.FormatConfig) *ChunkBuffer {
	return &ChunkBuffer{
		chunks: []string{},
		conf:   c,
	}
}

func (c *ChunkBuffer) Merge(nc *ChunkBuffer) {
	c.chunks = append(c.chunks, nc.chunks...)
}

func (c *ChunkBuffer) WriteString(s string) {
	c.chunks = append(c.chunks, s)
}

func (c *ChunkBuffer) String() string {
	return strings.Join(c.chunks, "")
}

func (c *ChunkBuffer) ChunkedString(level, offset int) string {
	var buf bytes.Buffer
	var isLineFeeded bool

	count := offset + level*c.conf.IndentWidth
	for i, b := range c.chunks {
		if isLineComment(b) {
			buf.WriteString(" " + b)
			buf.WriteString("\n")
			buf.WriteString(c.indent(level))
			if offset > 0 {
				buf.WriteString(c.offsetString(offset))
			}
			count = offset + level*c.conf.IndentWidth
			isLineFeeded = true
			continue
		}
		if count+len(b) > c.conf.LineWidth {
			buf.WriteString("\n")
			buf.WriteString(c.indent(level))
			if offset > 0 {
				buf.WriteString(c.offsetString(offset))
			}
			count = offset + level*c.conf.IndentWidth
		} else if i != 0 && !isLineFeeded {
			buf.WriteString(" ")
			count++
		}
		buf.WriteString(b)
		count += len(b)
		isLineFeeded = false
	}

	return buf.String()
}

func (c *ChunkBuffer) indent(level int) string {
	ws := " " // default as whitespace
	if c.conf.IndentStyle == config.IndentStyleTab {
		ws = "\t"
	}
	return strings.Repeat(ws, level*c.conf.IndentWidth)
}

func (c *ChunkBuffer) offsetString(offset int) string {
	ws := " " // default as whitespace
	if c.conf.IndentStyle == config.IndentStyleTab {
		ws = "\t"
	}
	return strings.Repeat(ws, offset)
}

func isLineComment(s string) bool {
	return strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#")
}
