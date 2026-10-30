// Runs only in Slack's main process; renderers keep their existing sandbox.
(() => {
  const { app, webContents } = require("electron");
  const fs = require("node:fs");
  const path = require("node:path");
  const directory = path.join(require("node:os").homedir(), ".local/state/omarchy/slack");
  const stylesheet = path.join(directory, "slack.css");
  const documents = new WeakMap();

  // Serialize updates per window so a slow insertion cannot restore an older
  // palette after a rapid sequence of theme changes.
  function apply(contents) {
    let state = documents.get(contents);
    if (!state) {
      state = { pending: Promise.resolve(), key: null, generation: 0 };
      documents.set(contents, state);
    }
    const generation = state.generation;
    state.pending = state.pending.then(async () => {
      if (contents.isDestroyed() || generation !== state.generation) return;
      const css = await fs.promises.readFile(stylesheet, "utf8");
      const key = await contents.insertCSS(css, { cssOrigin: "user" });
      if (contents.isDestroyed() || generation !== state.generation) return;
      const old = state.key;
      state.key = key;
      if (old) await contents.removeInsertedCSS(old);
    }).catch(error => console.warn("Omarchy Slack theme:", error.message));
  }

  app.on("web-contents-created", (_, contents) => {
    contents.on("dom-ready", () => {
      const state = documents.get(contents);
      if (state) {
        state.generation++;
        state.key = null;
      }
      apply(contents);
    });
  });

  // Watch the parent: theme writes atomically replace the stylesheet inode.
  // fs.watch uses filesystem events and starts no idle timer or helper process.
  try {
    const watcher = fs.watch(directory, (_, filename) => {
      if (filename === null || String(filename) === "slack.css") {
        webContents.getAllWebContents().forEach(apply);
      }
    });
    watcher.on("error", error => console.warn("Omarchy Slack theme:", error.message));
    app.once("will-quit", () => watcher.close());
  } catch (error) {
    console.warn("Omarchy Slack theme:", error.message);
  }
})();
