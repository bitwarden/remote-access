import { defineConfig } from "vite";
import { resolve } from "path";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  root: "www",
  plugins: [wasm()],
  resolve: {
    alias: {
      alpinejs: resolve(__dirname, "node_modules/alpinejs"),
    },
  },
  build: {
    target: "esnext",
  },
});
