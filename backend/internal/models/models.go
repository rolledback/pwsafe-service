package models

import "time"

type SafeFile struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	LastModified time.Time `json:"lastModified"`
	Source       string    `json:"source"`
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
	Groups  []*Group `json:"groups"`
	Entries []Entry  `json:"entries"`
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

// OneDrive models

type OneDriveStatus struct {
	Connected    bool   `json:"connected"`
	NeedsReauth  bool   `json:"needsReauth"`
	AccountName  string `json:"accountName,omitempty"`
	AccountEmail string `json:"accountEmail,omitempty"`
	LastSyncTime string `json:"lastSyncTime,omitempty"`
	NextSyncAt   string `json:"nextSyncAt,omitempty"`
}

type OneDriveAuthURL struct {
	URL string `json:"url"`
}

type OneDriveTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
	AccountName  string `json:"accountName"`
	AccountEmail string `json:"accountEmail"`
}

type OneDriveFile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Selected bool   `json:"selected"`
}

type OneDriveFilesResponse struct {
	Files []OneDriveFile `json:"files"`
}

type OneDriveFilesRequest struct {
	Files []OneDriveFile `json:"files"`
}

type OneDriveConfig struct {
	Files        []OneDriveFile `json:"files"`
	LastSyncTime string         `json:"lastSyncTime,omitempty"`
}

type OneDriveSyncResult struct {
	Name         string `json:"name"`
	Success      bool   `json:"success"`
	LastModified string `json:"lastModified,omitempty"`
	Error        string `json:"error,omitempty"`
}

type OneDriveSyncResponse struct {
	Results []OneDriveSyncResult `json:"results"`
}
