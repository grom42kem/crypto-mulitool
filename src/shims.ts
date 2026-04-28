import { Buffer } from "buffer";
import process from "process";
import { EventEmitter } from "events";
import Stream from "stream-browserify";

// esbuild --inject подключает это как "глобалы" для зависимостей,
// которые ожидают Node.js окружение.
(globalThis as any).Buffer = Buffer;
(globalThis as any).process = process;
(globalThis as any).global = globalThis;
(globalThis as any).EventEmitter = EventEmitter;
(globalThis as any).events = { EventEmitter };
(globalThis as any).stream = Stream;

