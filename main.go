package main

import (
	"bufio"
	"encoding/base32"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
)

// TOTP configuration
const (
	timeStep   = 30 // seconds
	codeDigits = 6
	configFile = ".gmfa.conf" // Default filename in home directory

	// ANSI escape code for bold text
	consoleBold = "\033[1m"
	// ANSI escape code to reset all formatting
	consoleReset = "\033[0m"
)

type TOTPEntry struct {
	Name   string
	Secret string
}

func main() {
	// Get the path to the config file in home directory
	secretFile, err := getConfigFilePath()
	if err != nil {
		fmt.Printf("Error determining config file path: %v\n", err)
		os.Exit(1)
	}

	// Read MFA secrets from file
	entries, err := readSecrets(secretFile)
	if err != nil || len(entries) == 0 {
		// File doesn't exist or is empty
		if err != nil {
			fmt.Printf("Secrets file not found or couldn't be read: %v\n", err)
		} else {
			fmt.Println("No MFA secrets found in the file.")
		}

		// Ask user to input URL via command line
		entries = promptForMFAUrl()

		// Save the URLs to the file for future use
		if len(entries) > 0 {
			err := saveSecrets(secretFile, entries)
			if err != nil {
				fmt.Printf("Warning: Failed to save secrets to %s: %v\n", secretFile, err)
			}
		} else {
			fmt.Println("No valid MFA URLs provided. Exiting.")
			os.Exit(1)
		}
	}

	clearScreen()
	fmt.Println("2FA TOTP Console Application")
	fmt.Println("-----------------------------")
	fmt.Printf("Loaded %d MFA entries from %s\n\n", len(entries), secretFile)

	// Display codes immediately first
	displayCodes(entries)

	// Calculate wait time to align with the next code rotation
	currentTime := time.Now().Unix()
	secondsRemaining := timeStep - (currentTime % timeStep)

	//fmt.Printf("\nNext code refresh in %d seconds\n", secondsRemaining)
	time.Sleep(time.Duration(secondsRemaining) * time.Second)

	// Main loop to display codes at each rotation
	for {
		clearScreen()
		displayCodes(entries)
		time.Sleep(time.Duration(timeStep) * time.Second)
	}
}

// Clear terminal screen based on OS
func clearScreen() {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		// For Linux, macOS, etc.
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}

// Display current TOTP codes
func displayCodes(entries []TOTPEntry) {
	currentTime := time.Now().Unix()
	validUntil := currentTime + (timeStep - (currentTime % timeStep))

	fmt.Printf("\nTOTP Codes (valid until %s):\n", time.Unix(validUntil, 0).Format("15:04:05"))
	fmt.Println("-----------------------------")

	for _, entry := range entries {
		code := generateTOTP(entry.Secret, currentTime)
		fmt.Printf(" * %-20s: %s%s%s\n", entry.Name, consoleBold, code, consoleReset)
	}
}

// Get the full path to the config file in the user's home directory
func getConfigFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %v", err)
	}

	return filepath.Join(homeDir, configFile), nil
}

// Prompt user to enter MFA URLs via command line
func promptForMFAUrl() []TOTPEntry {
	var entries []TOTPEntry
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Please enter your MFA URL(s).")
	fmt.Println("Format: otpauth://totp/Service:user@example.com?secret=ABCDEFGHIJKLMNOP&issuer=Service")
	fmt.Println("Enter an empty line when finished.")

	for {
		fmt.Print("Enter MFA URL: ")
		scanner.Scan()
		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			break // Empty line signals end of input
		}

		// Parse and validate the URL
		entry, err := parseOTPAuthURL(input)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		entries = append(entries, entry)
		fmt.Printf("Added: %s\n", entry.Name)
	}

	return entries
}

// Parse an otpauth URL and return a TOTPEntry
func parseOTPAuthURL(inputURL string) (TOTPEntry, error) {
	u, err := url.Parse(inputURL)
	if err != nil {
		return TOTPEntry{}, fmt.Errorf("invalid URL format: %v", err)
	}

	if u.Scheme != "otpauth" || u.Host != "totp" {
		return TOTPEntry{}, fmt.Errorf("URL must be an otpauth://totp URL")
	}

	path := strings.TrimPrefix(u.Path, "/")
	query := u.Query()
	secret := query.Get("secret")

	if secret == "" {
		return TOTPEntry{}, fmt.Errorf("missing 'secret' parameter in URL")
	}

	return TOTPEntry{
		Name:   path,
		Secret: secret,
	}, nil
}

// Save MFA secrets to file
func saveSecrets(filename string, entries []TOTPEntry) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header comments
	file.WriteString("# GMFA Secrets File\n")
	file.WriteString("# Format: otpauth://totp/Service:user@example.com?secret=ABCDEFGHIJKLMNOP&issuer=Service\n\n")

	// Write the URLs
	for _, entry := range entries {
		// Reconstruct a simplified URL
		line := fmt.Sprintf("otpauth://totp/%s?secret=%s\n", entry.Name, entry.Secret)
		file.WriteString(line)
	}

	fmt.Printf("Saved %d MFA entries to %s\n", len(entries), filename)
	return nil
}

// Read MFA secrets from file
func readSecrets(filename string) ([]TOTPEntry, error) {
	var entries []TOTPEntry

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Skip empty lines and comments
		}

		// Parse otpauth URL
		entry, err := parseOTPAuthURL(line)
		if err != nil {
			fmt.Printf("Warning: Skipping invalid MFA URL: %s (%v)\n", line, err)
			continue
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// Generate TOTP code
func generateTOTP(secret string, timestamp int64) string {
	// Decode the base32 secret
	secretBytes, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "ERROR"
	}

	// Calculate the counter value (number of time steps since Unix epoch)
	counter := timestamp / timeStep

	// Generate HMAC-SHA1
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, uint64(counter))

	mac := hmac.New(sha1.New, secretBytes)
	mac.Write(counterBytes)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	truncatedHash := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generate code with the required number of digits
	code := truncatedHash % uint32(pow10(codeDigits))
	return fmt.Sprintf("%0*d", codeDigits, code)
}

// Helper function to calculate 10^n
func pow10(n int) int {
	result := 1
	for i := 0; i < n; i++ {
		result *= 10
	}
	return result
}
