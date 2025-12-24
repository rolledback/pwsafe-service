const API_BASE_URL = "/api";

export type SafeFile = {
  name: string;
  path: string;
  lastModified: string;
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
};

export type EntryPasswordResponse = {
  password: string;
};

export const api = {
  async listSafes(): Promise<SafeFile[]> {
    const response = await fetch(`${API_BASE_URL}/safes`);
    if (!response.ok) {
      throw new Error("Failed to fetch safes");
    }
    return response.json();
  },

  async unlockSafe(filename: string, password: string): Promise<SafeStructure> {
    const response = await fetch(`${API_BASE_URL}/safes/${filename}/unlock`, {
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

  async getEntryPassword(filename: string, password: string, entryUuid: string): Promise<string> {
    const response = await fetch(`${API_BASE_URL}/safes/${filename}/entry`, {
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
};
