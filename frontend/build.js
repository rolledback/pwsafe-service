import * as esbuild from "esbuild";
import { copyFileSync, mkdirSync } from "fs";

const isProduction = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

const ctx = await esbuild.context({
  entryPoints: ["src/main.tsx"],
  bundle: true,
  outfile: "dist/bundle.js",
  minify: isProduction,
  sourcemap: !isProduction,
  target: ["es2020"],
  loader: {
    ".tsx": "tsx",
    ".ts": "ts",
  },
  jsx: "automatic",
});

mkdirSync("dist", { recursive: true });
copyFileSync("index.html", "dist/index.html");
copyFileSync("src/index.css", "dist/index.css");
copyFileSync("src/assets/favicons/vault-rose.svg", "dist/favicon.svg");

if (watch) {
  await ctx.watch();
  console.log("Watching for changes...");
} else {
  await ctx.rebuild();
  await ctx.dispose();
  console.log("Build complete!");
}
