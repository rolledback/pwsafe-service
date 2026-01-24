const API_BASE_URL = "/api";

export type SafeFile = {
  name: string;
  path: string;
  lastModified: string;
  source: "static" | "onedrive";
};

export type Entry = {
  uuid: string;
  title: string;
  username: string;
  url?: string;
  notes?: string;
};

export type Group = {
  name: string;
  groups?: Group[];
  entries?: Entry[];
};

export type SafeStructure = {
  groups: Group[];
  entries: Entry[];
};

export type EntryPasswordResponse = {
  password: string;
};

export type OneDriveStatus = {
  connected: boolean;
  needsReauth: boolean;
  accountName?: string;
  accountEmail?: string;
  lastSyncTime?: string;
  nextSyncAt?: string;
};

export type OneDriveAuthURL = {
  url: string;
};

export type OneDriveFile = {
  id: string;
  name: string;
  path: string;
  selected: boolean;
};

export type OneDriveFilesResponse = {
  files: OneDriveFile[];
};

export type OneDriveSyncResult = {
  name: string;
  success: boolean;
  lastModified?: string;
  error?: string;
};

export type OneDriveSyncResponse = {
  results: OneDriveSyncResult[];
};

export const api = {
  async listSafes(): Promise<SafeFile[]> {
    const response = await fetch(`${API_BASE_URL}/safes`);
    if (!response.ok) {
      throw new Error("Failed to fetch safes");
    }
    return response.json();
  },

  async unlockSafe(safePath: string, password: string): Promise<SafeStructure> {
    const encodedPath = encodeURIComponent(safePath);
    const response = await fetch(`${API_BASE_URL}/safes/${encodedPath}/unlock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to unlock safe");
    }

    return response.json();
  },

  async getEntryPassword(safePath: string, password: string, entryUuid: string): Promise<string> {
    const encodedPath = encodeURIComponent(safePath);
    const response = await fetch(`${API_BASE_URL}/safes/${encodedPath}/entry`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ password, entryUuid }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to get entry password");
    }

    const data: EntryPasswordResponse = await response.json();
    return data.password;
  },

  async getOneDriveStatus(): Promise<OneDriveStatus> {
    const response = await fetch(`${API_BASE_URL}/onedrive/status`);
    if (!response.ok) {
      throw new Error("Failed to get OneDrive status");
    }
    return response.json();
  },

  async getOneDriveAuthUrl(): Promise<OneDriveAuthURL> {
    const response = await fetch(`${API_BASE_URL}/onedrive/auth/url`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to get OneDrive auth URL");
    }
    return response.json();
  },

  async disconnectOneDrive(): Promise<{ success: boolean }> {
    const response = await fetch(`${API_BASE_URL}/onedrive/disconnect`, {
      method: "POST",
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to disconnect OneDrive");
    }
    return response.json();
  },

  async getOneDriveFiles(): Promise<OneDriveFilesResponse> {
    const response = await fetch(`${API_BASE_URL}/onedrive/files`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to get OneDrive files");
    }
    return response.json();
  },

  async saveOneDriveFiles(files: OneDriveFile[]): Promise<{ success: boolean }> {
    const response = await fetch(`${API_BASE_URL}/onedrive/files`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ files }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to save OneDrive files");
    }
    return response.json();
  },

  async syncOneDrive(): Promise<OneDriveSyncResponse> {
    const response = await fetch(`${API_BASE_URL}/onedrive/sync`, {
      method: "POST",
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to sync OneDrive files");
    }
    return response.json();
  },
};
