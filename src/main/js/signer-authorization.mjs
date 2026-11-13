function httpsUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === "https:" && !url.username && !url.password ? url : null;
    } catch {
        return null;
    }
}

export function authorizationTarget(value, configuredOrigins) {
    const target = httpsUrl(value);
    if (!target || !configuredOrigins.trim()) return target;

    const allowed = configuredOrigins.split(",").some(entry => {
        const value = entry.trim();
        const origin = httpsUrl(value);
        return origin && origin.href === origin.origin + "/" && origin.origin === target.origin;
    });
    return allowed ? target : null;
}
