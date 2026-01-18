package config

import (
	"os"
)

type Config struct {
	SafesDirectory      string
	ServerPort          string
	ServerHost          string
	OneDriveClientID    string
	OneDriveRedirectURI string
}

func Load() *Config {
	safesDir := os.Getenv("PWSAFE_DIRECTORY")
	if safesDir == "" {
		safesDir = "./testdata"
	}

	serverPort := os.Getenv("PWSAFE_PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	serverHost := os.Getenv("PWSAFE_HOST")
	if serverHost == "" {
		serverHost = "localhost"
	}

	oneDriveClientID := os.Getenv("ONEDRIVE_CLIENT_ID")

	oneDriveRedirectURI := os.Getenv("ONEDRIVE_REDIRECT_URI")
	if oneDriveRedirectURI == "" {
		oneDriveRedirectURI = "http://localhost:8080/api/onedrive/auth/callback"
	}

	return &Config{
		SafesDirectory:      safesDir,
		ServerPort:         serverPort,
		ServerHost:         serverHost,
		OneDriveClientID:    oneDriveClientID,
		OneDriveRedirectURI: oneDriveRedirectURI,
	}
}
