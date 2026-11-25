// Bundles src/app.ts + public/* into dist/index.tsx: one self-contained file for a Railway Function.
import fs from 'fs';
let code = fs.readFileSync('src/app.ts', 'utf8');
code = code.replace(/^import \{ Hono \} from 'hono';.*$/m, "import { Hono } from 'hono@4'; import bcrypt from 'bcryptjs@2'; import jwt from 'jsonwebtoken@9'; import crypto from 'crypto'; import Stripe from 'stripe@16'; import pg from 'pg@8';");
code = code.replace(/^const asset = .*$/m, "const SRC = await Bun.file(import.meta.path).text();\nconst asset = async (n: string) => SRC.split('/*@@' + n + '\\n')[1].split('\\n@@*/')[0];");
let out = code;
for (const f of ['index.html', 'logo.svg', 'logo-full.svg']) { const t = fs.readFileSync('public/' + f, 'utf8').trim(); if (t.includes('*/')) throw new Error(f + ' contains */'); out += `\n/*@@${f}\n${t}\n@@*/\n`; }
fs.mkdirSync('dist', { recursive: true }); fs.writeFileSync('dist/index.tsx', out); console.log('dist/index.tsx', out.length, 'bytes');
