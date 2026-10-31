package importer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/ledongthuc/pdf"

	"github.com/brett6320/recipe-manager/internal/recipes"
)

// maxPDFText caps extracted text so a hostile PDF cannot exhaust memory.
const maxPDFText = 512 << 10

// ParsePDF extracts text from a PDF and runs the text heuristics. The
// parser is third-party and recovers from panics on malformed input.
func ParsePDF(data []byte) (r *recipes.Recipe, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			r, err = nil, fmt.Errorf("could not read PDF: %v", rec)
		}
	}()
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, errors.New("not a PDF file")
	}
	reader, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, errors.New("could not read PDF")
	}
	if reader.NumPage() > 50 {
		return nil, errors.New("PDF has too many pages (max 50)")
	}
	var sb strings.Builder
	for i := 1; i <= reader.NumPage(); i++ {
		p := reader.Page(i)
		if p.V.IsNull() {
			continue
		}
		texts := p.Content().Text
		// Group glyph runs into lines by their Y coordinate (top to bottom),
		// then order each line left to right.
		sort.SliceStable(texts, func(i, j int) bool {
			if math.Abs(texts[i].Y-texts[j].Y) > 2 {
				return texts[i].Y > texts[j].Y
			}
			return texts[i].X < texts[j].X
		})
		var line strings.Builder
		lastY := math.Inf(1)
		lastX := 0.0
		for _, t := range texts {
			if math.Abs(t.Y-lastY) > 2 {
				if line.Len() > 0 {
					sb.WriteString(line.String())
					sb.WriteString("\n")
					line.Reset()
				}
				lastY = t.Y
			} else if t.X-lastX > t.FontSize*0.3 {
				line.WriteString(" ")
			}
			line.WriteString(t.S)
			lastX = t.X + t.W
			if sb.Len() > maxPDFText {
				break
			}
		}
		if line.Len() > 0 {
			sb.WriteString(line.String())
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	text := sb.String()
	if strings.TrimSpace(text) == "" {
		// Fall back to the plain extractor (some PDFs lack row metrics).
		rd, err := reader.GetPlainText()
		if err == nil {
			b, _ := io.ReadAll(io.LimitReader(rd, maxPDFText))
			text = string(b)
		}
	}
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("no text found in PDF (scanned image?)")
	}
	return ParseText(text), nil
}
