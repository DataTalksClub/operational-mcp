// Build the existing CLI at an immutable revision. Generated code stays out of public history.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { build } from 'esbuild';
const revision='5e25fc2ccdcb826c99282c049b28e56f3aaa55d5';
const temporary=process.argv[2]?null:mkdtempSync(join(tmpdir(),'mcp-dataops-build-'));
const directory=temporary?join(temporary,'dataops'):resolve(process.argv[2]);
try {
 if(temporary){execFileSync('git',['clone','--quiet','--filter=blob:none','https://github.com/DataTalksClub/dataops.git',directory],{stdio:'inherit'});execFileSync('git',['checkout','--quiet',revision],{cwd:directory,stdio:'inherit'});}
 else if(execFileSync('git',['rev-parse','HEAD'],{cwd:directory,encoding:'utf8'}).trim()!==revision)throw new Error('DataOps checkout must match the pinned revision');
 mkdirSync('vendor',{recursive:true});
 await build({entryPoints:[join(directory,'cli/bin/dataops.mjs')],outfile:'vendor/dataops.mjs',bundle:true,platform:'node',target:'node24',format:'esm'});
 console.log('Built pinned DataOps CLI (excluded from Git).');
} finally {if(temporary)rmSync(temporary,{recursive:true,force:true});}
