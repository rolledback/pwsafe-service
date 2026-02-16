const API_BASE_URL = "/api";

function getCsrfToken(): string {
  return (window as any).__PWSAFE_CSRF_TOKEN || "";
}

function apiHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "X-PWSAFE-CSRF-Token": getCsrfToken(), ...extra };
}

async function apiFetch(url: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(url, { ...init, credentials: "include" });
  if (response.status === 401) {
    window.location.href = "/web/login?expired=true";
    throw new Error("Session expired");
  }
  return response;
}

export type SafeFile = {
  id: string;
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
    const response = await apiFetch(`${API_BASE_URL}/safes`, {
      headers: apiHeaders(),
    });
    if (!response.ok) {
      throw new Error("Failed to fetch safes");
    }
    return response.json();
  },

  async unlockSafe(id: string, password: string): Promise<SafeStructure> {
    const response = await apiFetch(`${API_BASE_URL}/safes/${id}/unlock`, {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to unlock safe");
    }

    return response.json();
  },

  async getEntryPassword(id: string, password: string, entryUuid: string): Promise<string> {
    const response = await apiFetch(`${API_BASE_URL}/safes/${id}/entry`, {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
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
    const response = await apiFetch(`${API_BASE_URL}/providers`, {
      headers: apiHeaders(),
    });
    if (!response.ok) {
      throw new Error("Failed to list providers");
    }
    return response.json();
  },

  async getProviderStatus(providerId: string): Promise<ProviderStatus> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/status`, {
      headers: apiHeaders(),
    });
    if (!response.ok) {
      throw new Error(`Failed to get ${providerId} status`);
    }
    return response.json();
  },

  async getProviderAuthUrl(providerId: string): Promise<ProviderAuthURL> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/auth/url`, {
      headers: apiHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to get ${providerId} auth URL`);
    }
    return response.json();
  },

  async disconnectProvider(providerId: string): Promise<{ success: boolean }> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/disconnect`, {
      method: "POST",
      headers: apiHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to disconnect ${providerId}`);
    }
    return response.json();
  },

  async getProviderFiles(providerId: string): Promise<ProviderFilesResponse> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/files`, {
      headers: apiHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to get ${providerId} files`);
    }
    return response.json();
  },

  async saveProviderFiles(providerId: string, files: ProviderFile[]): Promise<{ success: boolean }> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/files`, {
      method: "PUT",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ files }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to save ${providerId} files`);
    }
    return response.json();
  },

  async syncProvider(providerId: string): Promise<ProviderSyncResponse> {
    const response = await apiFetch(`${API_BASE_URL}/providers/${providerId}/sync`, {
      method: "POST",
      headers: apiHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || `Failed to sync ${providerId} files`);
    }
    return response.json();
  },

  // Static provider APIs (upload/delete static safes)
  async uploadStaticSafe(file: File, overwrite?: boolean): Promise<{ success: boolean; name: string; exists?: boolean }> {
    const formData = new FormData();
    formData.append("file", file);

    const url = overwrite ? `${API_BASE_URL}/providers/static/files?overwrite=true` : `${API_BASE_URL}/providers/static/files`;

    const response = await apiFetch(url, {
      method: "POST",
      headers: apiHeaders(),
      body: formData,
    });

    const data = await response.json();

    if (response.status === 409) {
      // File exists, return conflict info
      return { success: false, name: data.name, exists: true };
    }

    if (!response.ok) {
      throw new Error(data.error || "Failed to upload safe");
    }

    return { success: true, name: data.name };
  },

  async deleteStaticSafe(id: string): Promise<{ success: boolean }> {
    const response = await apiFetch(`${API_BASE_URL}/providers/static/files/${id}`, {
      method: "DELETE",
      headers: apiHeaders(),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Failed to delete safe");
    }
    return response.json();
  },

  // Auth APIs
  async getAuthStatus(): Promise<{ mode: string; authenticated: boolean }> {
    const response = await fetch(`${API_BASE_URL}/auth/status`, { credentials: "include" });
    return response.json();
  },

  async authSetup(mode: string, password?: string): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/auth/setup`, {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({ mode, password }),
    });
    if (!response.ok) throw new Error((await response.text()).trim());
  },

  async login(password: string): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      credentials: "include",
      body: JSON.stringify({ password }),
    });
    if (!response.ok) throw new Error((await response.text()).trim());
  },

  async logout(): Promise<void> {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: "POST",
      headers: apiHeaders(),
      credentials: "include",
    });
  },
};
