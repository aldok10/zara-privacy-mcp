package privacy

type Finding struct {
	Type     string
	Value    string
	Position int
	Length   int
	Risk     int
}

type Masker interface {
	Mask(text string) (masked string, findings []Finding)
}
