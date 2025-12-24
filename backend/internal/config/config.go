package config

import (
	"os"
)

type Config struct {
	SafesDirectory string
	ServerPort     string
	ServerHost     string
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

	return &Config{
		SafesDirectory: safesDir,
		ServerPort:     serverPort,
		ServerHost:     serverHost,
	}
}
