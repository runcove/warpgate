function escapeUnix(arg: string): string {
    if (!/^[A-Za-z0-9_/-]+$/.test(arg)) {
        return `'${arg.replace(/'/g, "'\"'\"'")}'`.replace(/''/g, '')
    }
    return arg
}

function escapeWin(arg: string): string {
    if (!/^[A-Za-z0-9_/-]+$/.test(arg)) {
        return `"${arg.replace(/"/g, '""')}"`
    }
    return arg
}

// Whether the copied commands are quoted for a Windows shell. userAgentData is
// Chromium's; elsewhere the user agent string says "Windows" for every Windows.
function isWindows(): boolean {
    const platform = (
        navigator as Navigator & { userAgentData?: { platform?: string } }
    ).userAgentData?.platform
    if (platform) {
        return platform === 'Windows'
    }
    return /\bWindows\b/.test(navigator.userAgent)
}

const isWin = isWindows()

export function shellEscape(stringOrArray: string[] | string): string {
    const ret: string[] = []

    const escapePath = isWin ? escapeWin : escapeUnix

    if (typeof stringOrArray === 'string') {
        return escapePath(stringOrArray)
    } else {
        stringOrArray.forEach(member => {
            ret.push(escapePath(member))
        })
        return ret.join(' ')
    }
}
