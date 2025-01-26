import esbuild from "npm:esbuild";
import { wasmLoader } from "npm:esbuild-plugin-wasm";

await esbuild.build({
  entryPoints: ["./pkg/wasm_argon2.js"],
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
