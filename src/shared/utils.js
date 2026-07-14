export const CONFIG = {
  BACKEND_URL: 'https://trustpause.app/api',
  CACHE_TTL_MS: 24 * 60 * 60 * 1000, // 24 hours
  DRY_RUN: false // Set to true to only log without blocking
};

export function extractDomain(url) {
  try {
    const { hostname } = new URL(url);
    return hostname.replace(/^www\./, '').toLowerCase();
  } catch (e) {
    return null;
  }
}
