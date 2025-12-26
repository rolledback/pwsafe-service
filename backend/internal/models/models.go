package models

import "time"

type SafeFile struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	LastModified time.Time `json:"lastModified"`
}

type Group struct {
	Name    string   `json:"name"`
	Groups  []*Group `json:"groups,omitempty"`
	Entries []Entry  `json:"entries,omitempty"`
}

type Entry struct {
	UUID     string `json:"uuid"`
	Title    string `json:"title"`
	Username string `json:"username"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

type SafeStructure struct {
	Groups []*Group `json:"groups"`
}

type UnlockRequest struct {
	Password string `json:"password"`
}

type EntryPasswordRequest struct {
	Password  string `json:"password"`
	EntryUUID string `json:"entryUuid"`
}

type EntryPasswordResponse struct {
	Password string `json:"password"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
