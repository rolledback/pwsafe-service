const API_BASE_URL = "/api";

export type SafeFile = {
  name: string;
  path: string;
  lastModified: string;
  provider: string; // Provider ID (e.g., "local", "onedrive", "gdrive")
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

// Provider types
export type Provider = {
  id: string;
  displayName: string;
  icon: string;
  brandColor: string;
};

export type ProvidersResponse = {
  providers: Provider[];
};

export type ProviderStatus = {
  connected: boolean;
  needsReauth: boolean;
  accountName?: string;
  accountEmail?: string;
  lastSyncTime?: string;
  nextSyncAt?: string;
};

export type ProviderAuthURL = {
  url: string;
};

export type ProviderFile = {
  id: string;
  name: string;
  path: string;
  selected: boolean;
};

export type ProviderFilesResponse = {
  files: ProviderFile[];
};

export type ProviderSyncResult = {
  name: string;
  success: boolean;
  lastModified?: string;
  error?: string;
};

export type ProviderSyncResponse = {
  results: ProviderSyncResult[];
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

  // Provider APIs
  async listProviders(): Promise<ProvidersResponse> {
    const response = await fetch(`${API_BASE_URL}/providers`);
    if (!response.ok) {
      throw new Error("Failed to list providers");
    }
    return response.json();
  },

  async getProviderStatus(providerId: string): Promise<ProviderStatus> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/status`);
    if (!response.ok) {
      throw new Error(`Failed to get ${providerId} status`);
    }
    return response.json();
  },

  async getProviderAuthUrl(providerId: string): Promise<ProviderAuthURL> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/auth/url`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to get ${providerId} auth URL`);
    }
    return response.json();
  },

  async disconnectProvider(providerId: string): Promise<{ success: boolean }> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/disconnect`, {
      method: "POST",
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to disconnect ${providerId}`);
    }
    return response.json();
  },

  async getProviderFiles(providerId: string): Promise<ProviderFilesResponse> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/files`);
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to get ${providerId} files`);
    }
    return response.json();
  },

  async saveProviderFiles(providerId: string, files: ProviderFile[]): Promise<{ success: boolean }> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/files`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ files }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to save ${providerId} files`);
    }
    return response.json();
  },

  async syncProvider(providerId: string): Promise<ProviderSyncResponse> {
    const response = await fetch(`${API_BASE_URL}/providers/${providerId}/sync`, {
      method: "POST",
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to sync ${providerId} files`);
    }
    return response.json();
  },
};
