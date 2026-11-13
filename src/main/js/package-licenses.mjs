import { copyFile, mkdir, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const { packages } = JSON.parse(await readFile("package-lock.json", "utf8"));
const destination = "target/generated-resources/META-INF/third-party";
await mkdir(destination, { recursive: true });

for (const [path, info] of Object.entries(packages)) {
    if (!path || info.dev || info.optional) continue;
    const files = await readdir(path);
    const license = files.find(file => /^(?:UN)?LICEN[CS]E(?:\.[^.]+)?$/i.test(file));
    if (!license) throw new Error("No license file for " + path);
    const name = path.split("node_modules/").at(-1).replaceAll("/", "-");
    await copyFile(join(path, license), join(destination, name + "-LICENSE.txt"));
}
