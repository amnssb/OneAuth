package session

// GenerateRandomHex exports the random hex generator for external use
func GenerateRandomHex(length int) (string, error) {
	return generateRandomHex(length)
}
