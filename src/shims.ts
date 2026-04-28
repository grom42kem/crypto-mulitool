import { Buffer } from "buffer";
import process from "process";

// esbuild --inject подключает это как "глобалы" для зависимостей,
// которые ожидают Node.js окружение.
(globalThis as any).Buffer = Buffer;
(globalThis as any).process = process;
(globalThis as any).global = globalThis;

