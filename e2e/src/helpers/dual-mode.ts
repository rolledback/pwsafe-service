import { describe, beforeAll, afterAll } from "vitest";
import { ServerInstance, ServerOptions } from "./server";
import { ApiClient } from "./api-client";

export function describeDualMode(
  name: string,
  extraOptions: Partial<ServerOptions>,
  fn: (getApi: () => ApiClient, getServer: () => ServerInstance) => void,
) {
  for (const mode of ["unsecured", "secured"] as const) {
    describe(`${name} (${mode})`, () => {
      let server: ServerInstance;
      let api: ApiClient;

      beforeAll(async () => {
        server = new ServerInstance({ ...extraOptions, authMode: mode, password: "testpass" });
        await server.start();
        api = new ApiClient(server.baseUrl, server.apiToken);
        if (mode === "secured") await api.login("testpass");
      });

      afterAll(async () => {
        await server.stop();
      });

      fn(
        () => api,
        () => server,
      );
    });
  }
}
