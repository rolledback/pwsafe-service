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

// Settings represents the parsed settings.json file
type Settings struct {
	BaseURL   string                       `json:"baseUrl"`
	Providers map[string]map[string]any    `json:"providers"`
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
func LoadSettings(configDir string) (*Settings, error) {
	settingsPath := filepath.Join(configDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read settings.json: %w", err)
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("failed to parse settings.json: %w", err)
	}

	return &settings, nil
}
