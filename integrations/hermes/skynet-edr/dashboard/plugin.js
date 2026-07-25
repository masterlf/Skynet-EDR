(function () {
  "use strict";

  const registry = window.__HERMES_PLUGINS__;
  if (!registry || typeof registry.register !== "function") return;

  function SkynetEdrBackendCompanion() {
    return null;
  }

  registry.register("skynet-edr", SkynetEdrBackendCompanion);
})();
