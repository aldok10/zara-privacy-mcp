package compress

import (
	"strings"
	"testing"
)

func TestCompress_Dedup(t *testing.T) {
	c := NewCompressor(4096)
	input := "line1\nline1\nline1\nline2"
	result := c.Compress(input, nil)
	if strings.Count(result, "line1") > 1 {
		t.Error("expected deduplication")
	}
}

func TestCompress_StripComments(t *testing.T) {
	c := NewCompressor(4096)
	input := "code here\n// this is a comment\nmore code\n# another comment"
	result := c.Compress(input, nil)
	if strings.Contains(result, "// this is") {
		t.Error("expected // comments stripped")
	}
	if strings.Contains(result, "# another") {
		t.Error("expected # comments stripped")
	}
}

func TestCompress_WithKeywords(t *testing.T) {
	c := NewCompressor(4096)
	input := "alpha line\nbeta important\ngamma line\ndelta important"
	result := c.Compress(input, []string{"important"})
	if !strings.Contains(result, "important") {
		t.Error("expected keyword lines retained")
	}
}

func TestCompress_Empty(t *testing.T) {
	c := NewCompressor(4096)
	result := c.Compress("", nil)
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDedupLines(t *testing.T) {
	c := NewCompressor(4096)
	input := "a\nb\na\nc\nb"
	result := c.DedupLines(input)
	if strings.Count(result, "a") != 1 {
		t.Error("expected 'a' deduped")
	}
	if strings.Count(result, "b") != 1 {
		t.Error("expected 'b' deduped")
	}
}

func TestDedupLines_SingleLine(t *testing.T) {
	c := NewCompressor(4096)
	result := c.DedupLines("single")
	if result != "single" {
		t.Errorf("expected 'single', got %q", result)
	}
}

func TestRemoveComments(t *testing.T) {
	c := NewCompressor(4096)
	input := "code\n// comment\n-- sql comment\nmore code"
	result := c.RemoveComments(input, []string{"//", "--"})
	if strings.Contains(result, "// comment") {
		t.Error("expected // comment removed")
	}
	if strings.Contains(result, "-- sql") {
		t.Error("expected -- comment removed")
	}
	if !strings.Contains(result, "code") {
		t.Error("expected code retained")
	}
}

func TestExtractRelevant_NoKeywords(t *testing.T) {
	c := NewCompressor(4096)
	input := "line1\nline2\nline3"
	result := c.ExtractRelevant(input, nil, 1)
	if result != input {
		t.Error("expected original text when no keywords")
	}
}

func TestExtractRelevant_WithContext(t *testing.T) {
	c := NewCompressor(4096)
	input := "line0\nline1\ntarget\nline3\nline4"
	result := c.ExtractRelevant(input, []string{"target"}, 1)
	if !strings.Contains(result, "target") {
		t.Error("expected target line")
	}
	if !strings.Contains(result, "line1") {
		t.Error("expected context line before")
	}
	if !strings.Contains(result, "line3") {
		t.Error("expected context line after")
	}
}

func TestExtractRelevant_NoMatch(t *testing.T) {
	c := NewCompressor(4096)
	input := "line1\nline2"
	result := c.ExtractRelevant(input, []string{"nonexistent"}, 1)
	if result != input {
		t.Error("expected original when no match")
	}
}

func TestTFIDFExtractor_TopLines(t *testing.T) {
	e := NewTFIDFExtractor()
	input := "unique rare word\nthe a an\nanother unique phrase"
	result := e.TopLines(input, 2)
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestTFIDFExtractor_ScoreLines(t *testing.T) {
	e := NewTFIDFExtractor()
	scores := e.ScoreLines("hello world\nhello hello\nunique")
	if len(scores) != 3 {
		t.Errorf("expected 3 scores, got %d", len(scores))
	}
}
