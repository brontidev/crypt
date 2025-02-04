import esbuild from "esbuild";
import { wasmLoader } from "esbuild-plugin-wasm";

await esbuild.build({
  entryPoints: ["./pkg/wasm_bcrypt.js"],
  bundle: true,
  outdir: "out",
  format: "esm",
  banner: { js: `/// <reference types="./wasm.d.ts" />` },
  plugins: [
    wasmLoader({
      mode: "embedded",
    }),
  ],
});
