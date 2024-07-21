package mail

import "os"


// Wite a file with the given content
func WriteFile(file_path string, decodedContent []byte) error {
	file, err := os.Create(file_path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(string(decodedContent))
	if err != nil {
		return err
	}
	return nil
}