// Package compress provides context compression utilities.
// Phase 2: deterministic compression (dedup, extractive) first, LLM-based later.
package compress

import (
	"sort"
	"strings"
	"unicode"
)

// Compressor handles context compression strategies.
type Compressor struct {
	maxTokens int
}

// NewCompressor creates a compressor with a target token budget.
func NewCompressor(maxTokens int) *Compressor {
	return &Compressor{maxTokens: maxTokens}
}

// DedupLines removes duplicate consecutive lines.
func (c *Compressor) DedupLines(text string) string {
	lines := strings.Split(text, "\n")
	if len(lines) <= 1 {
		return text
	}

	var result []string
	seen := make(map[string]int)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			result = append(result, line)
			continue
		}
		if _, exists := seen[trimmed]; !exists {
			seen[trimmed] = 1
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// DedupBlocks removes near-duplicate blocks of text (e.g., repeated error messages).
func (c *Compressor) DedupBlocks(text string, minBlockLen int) string {
	// For now, this is a simple implementation.
	// Phase 2 will add proper TF-IDF based dedup.
	return c.DedupLines(text)
}

// RemoveComments removes common comment patterns.
func (c *Compressor) RemoveComments(text string, commentPrefixes []string) string {
	lines := strings.Split(text, "\n")
	var result []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		skip := false
		for _, prefix := range commentPrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// ExtractRelevant extracts the most relevant portions based on keyword matching.
// Simple approach; Phase 2 will add TF-IDF and semantic extraction.
func (c *Compressor) ExtractRelevant(text string, keywords []string, contextLines int) string {
	if len(keywords) == 0 {
		return text
	}

	lines := strings.Split(text, "\n")
	relevant := make(map[int]bool)

	kwLower := make([]string, len(keywords))
	for i, k := range keywords {
		kwLower[i] = strings.ToLower(k)
	}

	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, kw := range kwLower {
			if strings.Contains(lower, kw) {
				// Mark surrounding lines
				for j := max(0, i-contextLines); j <= min(len(lines)-1, i+contextLines); j++ {
					relevant[j] = true
				}
				break
			}
		}
	}

	// If nothing matched, return original
	if len(relevant) == 0 {
		return text
	}

	var result []string
	for i := 0; i < len(lines); i++ {
		if relevant[i] {
			result = append(result, lines[i])
		}
	}

	return strings.Join(result, "\n")
}

// Compress applies all compression strategies in sequence.
func (c *Compressor) Compress(text string, keywords []string) string {
	result := c.DedupLines(text)
	result = c.RemoveComments(result, []string{"//", "#", "--"})

	if len(keywords) > 0 {
		result = c.ExtractRelevant(result, keywords, 3)
	}

	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TFIDFExtractor scores lines by TF-IDF against a corpus.
// Stub for Phase 2.
type TFIDFExtractor struct {
	stopWords map[string]bool
}

// NewTFIDFExtractor creates a TF-IDF extractor.
func NewTFIDFExtractor() *TFIDFExtractor {
	e := &TFIDFExtractor{
		stopWords: make(map[string]bool),
	}
	e.initStopWords()
	return e
}

func (e *TFIDFExtractor) initStopWords() {
	words := []string{"the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
		"of", "with", "by", "from", "as", "is", "was", "are", "were", "be", "been",
		"being", "have", "has", "had", "do", "does", "did", "will", "would", "could",
		"should", "may", "might", "shall", "can", "need", "dare", "ought", "used",
		"this", "that", "these", "those", "i", "you", "he", "she", "it", "we", "they",
		"my", "your", "his", "her", "its", "our", "their", "me", "him", "us", "them"}
	for _, w := range words {
		e.stopWords[w] = true
	}
}

// ScoreLines returns a map of line index to relevance score.
func (e *TFIDFExtractor) ScoreLines(text string) map[int]float64 {
	lines := strings.Split(text, "\n")
	scores := make(map[int]float64)

	// Simple frequency-based scoring (Phase 2 will improve)
	docFreq := make(map[string]int)
	lineTerms := make(map[int][]string)

	for i, line := range lines {
		terms := tokenize(line)
		lineTerms[i] = terms
		seen := make(map[string]bool)
		for _, t := range terms {
			if !seen[t] {
				docFreq[t]++
				seen[t] = true
			}
		}
	}

	nLines := len(lines)
	for i, terms := range lineTerms {
		var score float64
		termFreq := make(map[string]int)
		for _, t := range terms {
			termFreq[t]++
		}
		for t, tf := range termFreq {
			idf := 1.0
			if df := docFreq[t]; df > 0 {
				idf = 1.0 + float64(nLines)/float64(df)
			}
			score += float64(tf) * idf
		}
		scores[i] = score
	}

	return scores
}

// TopLines returns the top N scored lines.
func (e *TFIDFExtractor) TopLines(text string, n int) string {
	scores := e.ScoreLines(text)
	lines := strings.Split(text, "\n")

	type scoredLine struct {
		index int
		score float64
		line  string
	}

	var scored []scoredLine
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		scored = append(scored, scoredLine{i, scores[i], line})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	if n > len(scored) {
		n = len(scored)
	}

	// Re-sort by original position
	result := scored[:n]
	sort.Slice(result, func(i, j int) bool {
		return result[i].index < result[j].index
	})

	var sb strings.Builder
	for i, s := range result {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(s.line)
	}

	return sb.String()
}

func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder

	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current.WriteRune(r)
		} else {
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}
