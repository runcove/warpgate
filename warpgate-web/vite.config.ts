import { svelte } from '@sveltejs/vite-plugin-svelte'
import { defineConfig } from 'vite'
import { bundleLicenses } from './build/bundle-licenses.ts'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [svelte(), bundleLicenses()],
    base: '/@warpgate',
    build: {
        sourcemap: true,
        manifest: true,
        commonjsOptions: {
            include: [
                'src/gateway/lib/api-client/dist/*.js',
                'src/admin/lib/api-client/dist/*.js',
                '**/*.js',
            ],
            transformMixedEsModules: true,
        },
        rollupOptions: {
            input: {
                admin: 'src/admin/index.html',
                gateway: 'src/gateway/index.html',
                embed: 'src/embed/index.ts',
            },
        },
    },
    resolve: {
        tsconfigPaths: true,
    },
})
