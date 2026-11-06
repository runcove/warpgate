// Generates one typed API client (admin or gateway) from its checked-in OpenAPI schema.
//
//   node scripts/openapi-client.mjs <admin|gateway>
//
// Everything this runs is pinned:
//   - the generator jar is the version in openapi-generator.pin.json and is refused unless its
//     sha256 matches (the CLI package only checks the version number, never the bytes);
//   - the generated client is compiled with the TypeScript in package-lock.json, and nothing is
//     installed inside the client directory (the typescript-fetch output has no runtime
//     dependencies, so there is nothing for a client-side `npm install` to resolve).
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const pin = JSON.parse(
    fs.readFileSync(path.join(root, 'openapi-generator.pin.json'), 'utf8'),
)
const jarDir = path.join(root, '.openapi-generator')
const jarPath = path.join(jarDir, `openapi-generator-cli-${pin.version}.jar`)

export function sha256File(file) {
    return crypto
        .createHash('sha256')
        .update(fs.readFileSync(file))
        .digest('hex')
}

export function verifyJar(file, expected) {
    const actual = sha256File(file)
    if (actual !== expected) {
        throw new Error(
            `${file}: sha256 is ${actual}, expected ${expected}; refusing to run it`,
        )
    }
}

async function ensureJar() {
    if (fs.existsSync(jarPath)) {
        verifyJar(jarPath, pin.sha256)
        return
    }
    fs.mkdirSync(jarDir, { recursive: true })
    const response = await fetch(pin.url)
    if (!response.ok) {
        throw new Error(`downloading ${pin.url}: HTTP ${response.status}`)
    }
    const partial = `${jarPath}.${process.pid}.part`
    fs.writeFileSync(partial, Buffer.from(await response.arrayBuffer()))
    try {
        verifyJar(partial, pin.sha256)
    } catch (error) {
        fs.rmSync(partial, { force: true })
        throw error
    }
    fs.renameSync(partial, jarPath)
}

function run(command, args, cwd) {
    const result = spawnSync(command, args, { cwd, stdio: 'inherit' })
    if (result.error) {
        throw result.error
    }
    if (result.status !== 0) {
        throw new Error(
            `${command} ${args[0] ?? ''} exited with ${result.status}`,
        )
    }
}

async function main(target) {
    if (target !== 'admin' && target !== 'gateway') {
        throw new Error('usage: openapi-client.mjs <admin|gateway>')
    }
    await ensureJar()

    const client = path.join(root, 'src', target, 'lib', 'api-client')
    run(
        'java',
        [
            '-jar',
            jarPath,
            'generate',
            '-g',
            'typescript-fetch',
            '-i',
            path.join(root, 'src', target, 'lib', 'openapi-schema.json'),
            '-o',
            client,
            '-p',
            `npmName=warpgate-${target}-api-client`,
            '-p',
            'useSingleRequestParameter=true',
        ],
        root,
    )

    // The TypeScript from package-lock.json, not whatever `npm i typescript@5` resolves today.
    const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc')
    run(
        process.execPath,
        [tsc, '--target', 'esnext', '--module', 'esnext'],
        client,
    )

    fs.rmSync(path.join(client, 'src'), { recursive: true, force: true })
    fs.rmSync(path.join(client, 'tsconfig.json'), { force: true })
}

if (
    process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
    main(process.argv[2]).catch(error => {
        console.error(`openapi-client: ${error.message}`)
        process.exit(1)
    })
}
