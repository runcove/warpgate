// Whether the browser runs on Windows, so the copied commands are quoted for a
// Windows shell. This follows ua-parser-js's rules for the OS it names
// "Windows": "Windows NT" (but not an Xbox), Win32/Win64/WinNT/Win9x and the
// named releases, matched in any case, since some Windows browsers (WeChat,
// QQBrowser, Quark) send their user agent in lower case. Old Windows Phones also
// say "Windows NT" and are not Windows. Windows RT is: it has cmd.exe.
const WINDOWS =
    /windows nt(?!.+xbox)|\bwin(?=3| ?9|n)|windows[/ ](?:1[01]|2000|3\.1|7|8|9[58]|me|server 20\d\d|vista|xp)/i
const WINDOWS_PHONE = /windows phone/i

export function isWindowsUserAgent(
    userAgent: string,
    platform?: string,
): boolean {
    // userAgentData.platform is Chromium's and names the OS outright.
    if (platform) {
        return platform === 'Windows'
    }
    return WINDOWS.test(userAgent) && !WINDOWS_PHONE.test(userAgent)
}

export function isWindowsBrowser(): boolean {
    const platform = (
        navigator as Navigator & { userAgentData?: { platform?: string } }
    ).userAgentData?.platform
    return isWindowsUserAgent(navigator.userAgent, platform)
}
