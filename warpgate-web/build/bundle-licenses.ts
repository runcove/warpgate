// Records which npm packages end up in the built web UI, with each package's declared
// licence and the licence and notice files it ships, so the release's third-party notices
// can list them. Minification strips those notices from the bundle itself.
//
// A package counts when any of its files reaches the output: code left in a chunk after
// tree-shaking, CSS, an emitted asset (fonts), or a stylesheet Sass pulled in with @import
// (bootstrap), which never becomes a module of its own and is seen by a Sass importer.
//
// The manifest goes to dist-licenses/bundle-licenses.json, beside dist and not inside it:
// everything in dist is embedded in the binary and served. This file only records; which
// licences are acceptable is decided by whoever builds the notices from it.
import {
    existsSync,
    mkdirSync,
    readdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import type { Plugin } from 'vite'

const OUT_DIR = 'dist-licenses'
const OUT_FILE = 'bundle-licenses.json'
const NODE_MODULES = '/node_modules/'
const LICENCE_FILE =
    /^(licen[sc]e|copying|notice|unlicen[sc]e|ofl)(?:[-_.].*)?$/i
const STYLESHEET = /\.(css|scss|sass)$/

interface Found {
    name: string
    dir: string
    via: Set<string>
}

type LicenseField = string | { type?: string } | undefined

interface PackageJson {
    name?: string
    version?: string
    license?: LicenseField
    licenses?: LicenseField[]
    repository?: string | { url?: string }
}

/** The package name at the start of a bare specifier or a path below node_modules. */
function packageName(spec: string): string {
    const parts = spec.split('/')
    return parts.slice(0, parts[0]?.startsWith('@') ? 2 : 1).join('/')
}

/** The package a file path belongs to (the innermost node_modules entry), or null. */
function packageOf(path: string): { name: string; dir: string } | null {
    const p = (path.split('?')[0] ?? '').replace(/\\/g, '/')
    const at = p.lastIndexOf(NODE_MODULES)
    if (p.startsWith('\0') || at === -1) {
        return null
    }
    const rest = p.slice(at + NODE_MODULES.length)
    const name = packageName(rest)
    if (name.startsWith('.') || rest.length <= name.length) {
        return null
    }
    return { name, dir: p.slice(0, at + NODE_MODULES.length) + name }
}

function licenseType(l: LicenseField): string {
    return (typeof l === 'string' ? l : (l?.type ?? '')).trim()
}

function declaredLicense(pkg: PackageJson): string {
    if (pkg.license !== undefined) {
        return licenseType(pkg.license)
    }
    return (pkg.licenses ?? []).map(licenseType).filter(Boolean).join(' OR ')
}

function readPackage(f: Found) {
    const pkg: PackageJson = JSON.parse(
        readFileSync(join(f.dir, 'package.json'), 'utf8'),
    )
    const files = readdirSync(f.dir, { withFileTypes: true })
        .filter(e => e.isFile() && LICENCE_FILE.test(e.name))
        .map(e => e.name)
        .sort()
        .map(name => ({
            name,
            text: readFileSync(join(f.dir, name), 'utf8').replace(
                /\r\n/g,
                '\n',
            ),
        }))
    return {
        name: pkg.name ?? f.name,
        version: pkg.version ?? '',
        license: declaredLicense(pkg),
        repository:
            typeof pkg.repository === 'string'
                ? pkg.repository
                : (pkg.repository?.url ?? ''),
        via: [...f.via].sort(),
        files,
    }
}

export function bundleLicenses(): Plugin {
    const found = new Map<string, Found>()
    const sassImports = new Set<string>()
    let root = ''
    let outDir = ''
    const add = (path: string, via: string) => {
        const p = packageOf(path)
        if (!p) {
            return
        }
        const f = found.get(p.dir) ?? { ...p, via: new Set<string>() }
        f.via.add(via)
        found.set(p.dir, f)
    }
    return {
        name: 'warpgate-bundle-licenses',
        apply: 'build',
        config() {
            // Ahead of Vite's own importer, which resolves the import; this one only notes the
            // package of each bare @import (bootstrap/scss/...) and lets resolution go on.
            const recorder = {
                findFileUrl(url: string) {
                    if (!/^(\.|\/|[a-z]+:)/i.test(url)) {
                        sassImports.add(packageName(url.replace(/^~/, '')))
                    }
                    return null
                },
            }
            return {
                css: {
                    preprocessorOptions: { scss: { importers: [recorder] } },
                },
            }
        },
        configResolved(config) {
            root = config.root
            outDir = resolve(root, config.build.outDir)
        },
        generateBundle(_options, bundle) {
            for (const item of Object.values(bundle)) {
                if (item.type === 'chunk') {
                    for (const [id, info] of Object.entries(item.modules)) {
                        // Tree-shaken to nothing: no code of it is in the chunk. CSS is
                        // extracted, so its modules render empty but still ship.
                        if (info.renderedLength > 0) {
                            add(id, 'code')
                        } else if (STYLESHEET.test(id.split('?')[0] ?? '')) {
                            add(id, 'css')
                        }
                    }
                } else {
                    for (const name of item.originalFileNames ?? []) {
                        add(resolve(root, name), 'asset')
                    }
                }
            }
            // A bare @import that Sass found on a load path is not a package.
            for (const name of sassImports) {
                const manifest = join(
                    root,
                    'node_modules',
                    name,
                    'package.json',
                )
                if (existsSync(manifest)) {
                    add(manifest, 'sass')
                }
            }
        },
        writeBundle() {
            const packages = [...found.values()]
                .map(readPackage)
                .sort(
                    (a, b) =>
                        a.name.localeCompare(b.name, 'en') ||
                        a.version.localeCompare(b.version, 'en'),
                )
            const dir = join(dirname(outDir), OUT_DIR)
            mkdirSync(dir, { recursive: true })
            writeFileSync(join(dir, '.gitignore'), '*\n')
            writeFileSync(
                join(dir, OUT_FILE),
                `${JSON.stringify({ schema: 1, packages }, null, 2)}\n`,
            )
            console.log(
                `bundle-licenses: ${packages.length} npm packages -> ${OUT_DIR}/${OUT_FILE}`,
            )
        },
    }
}
