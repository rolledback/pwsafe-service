package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Config struct {
	ConfigDirectory string
	DataDirectory   string
	StaticDir       string
	ServerPort      string
	ServerHost      string
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Mode           string `json:"mode"`           // "unsecured", "secured", or "" (unset)
	SessionTimeout string `json:"sessionTimeout"` // duration string, default "3m"
}

// Settings represents the parsed settings.json file
type Settings struct {
	BaseURL      string                    `json:"baseUrl"`
	SyncInterval string                    `json:"syncInterval"`
	Auth         *AuthConfig               `json:"auth,omitempty"`
	Providers    map[string]map[string]any `json:"providers"`
}

// SaveSettings writes settings back to settings.json in the config directory
func SaveSettings(configDir string, settings *Settings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}
	settingsPath := filepath.Join(configDir, "settings.json")
	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write settings.json: %w", err)
	}
	return nil
}

func Load() *Config {
	configDir := os.Getenv("PWSAFE_CONFIG_DIR")
	dataDir := os.Getenv("PWSAFE_DATA_DIR")
	staticDir := os.Getenv("PWSAFE_STATIC_DIR")
	serverPort := os.Getenv("PWSAFE_PORT")

	if configDir == "" || dataDir == "" || staticDir == "" {
		log.Fatal("PWSAFE_CONFIG_DIR, PWSAFE_DATA_DIR, and PWSAFE_STATIC_DIR must be set")
	}

	// Determine if running in Docker (all env vars set to Docker defaults)
	isDocker := configDir == "/config" && dataDir == "/data"

	if serverPort == "" {
		serverPort = "8080"
	}

	// Hardcode host based on environment
	serverHost := "localhost"
	if isDocker {
		serverHost = "0.0.0.0"
	}

	return &Config{
		ConfigDirectory: configDir,
		DataDirectory:   dataDir,
		StaticDir:       staticDir,
		ServerPort:      serverPort,
		ServerHost:      serverHost,
	}
}

// LoadSettings reads and parses the settings.json from the config directory
// Returns default settings if the file doesn't exist or is empty
func LoadSettings(configDir string) (*Settings, error) {
	settingsPath := filepath.Join(configDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("No settings.json found, using defaults")
			return &Settings{}, nil
		}
		return nil, fmt.Errorf("failed to read settings.json: %w", err)
	}

	// Handle empty file
	if len(data) == 0 {
		log.Printf("Empty settings.json, using defaults")
		return &Settings{}, nil
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings.json: %w", err)
	}

	return &settings, nil
}
