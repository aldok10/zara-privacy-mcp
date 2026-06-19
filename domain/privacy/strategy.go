package privacy

// DetectionStrategy defines a strategy for detecting sensitive data.
// Multiple strategies can be composed (regex, entropy, context-aware).
type DetectionStrategy interface {
	// Name returns the strategy identifier.
	Name() string
	// Detect scans text and returns findings.
	Detect(text string, opts ...DetectOption) []Finding
}

// DetectOption configures detection behavior.
type DetectOption func(*detectConfig)

type detectConfig struct {
	Locales    []string
	MinRisk    int
	MaxResults int
}

// WithLocales filters detection by locale.
func WithLocales(locales ...string) DetectOption {
	return func(c *detectConfig) { c.Locales = locales }
}

// WithMinRisk sets minimum risk threshold for findings.
func WithMinRisk(risk int) DetectOption {
	return func(c *detectConfig) { c.MinRisk = risk }
}

// WithMaxResults caps the number of returned findings.
func WithMaxResults(max int) DetectOption {
	return func(c *detectConfig) { c.MaxResults = max }
}

// CompositeDetector chains multiple strategies together.
// Results are merged and deduplicated by position.
type CompositeDetector struct {
	strategies []DetectionStrategy
}

// NewCompositeDetector creates a detector that runs all strategies.
func NewCompositeDetector(strategies ...DetectionStrategy) *CompositeDetector {
	return &CompositeDetector{strategies: strategies}
}

// Detect runs all strategies and returns merged, deduplicated findings.
func (c *CompositeDetector) Detect(text string, opts ...DetectOption) []Finding {
	var all []Finding
	seen := make(map[int]bool) // deduplicate by position

	for _, s := range c.strategies {
		findings := s.Detect(text, opts...)
		for _, f := range findings {
			if !seen[f.Position] {
				seen[f.Position] = true
				all = append(all, f)
			}
		}
	}
	return all
}

// Strategies returns the registered strategy names.
func (c *CompositeDetector) Strategies() []string {
	names := make([]string, len(c.strategies))
	for i, s := range c.strategies {
		names[i] = s.Name()
	}
	return names
}
