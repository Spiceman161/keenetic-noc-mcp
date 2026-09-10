import type { AuthMode } from '../config/load.js';

/**
 * Transliteration used only to derive a convenient local profile identifier.
 * The router's display name is retained separately and is never rewritten.
 */
const CYRILLIC_TO_ASCII: Readonly<Record<string, string>> = {
  а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ё: 'yo', ж: 'zh', з: 'z',
  и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r',
  с: 's', т: 't', у: 'u', ф: 'f', х: 'kh', ц: 'ts', ч: 'ch', ш: 'sh',
  щ: 'shch', ъ: '', ы: 'y', ь: '', э: 'e', ю: 'yu', я: 'ya',
  є: 'ye', і: 'i', ї: 'yi', ґ: 'g', ў: 'u', ђ: 'dj', ј: 'j', љ: 'lj',
  њ: 'nj', ћ: 'c', џ: 'dz', ѕ: 'dz', ќ: 'k'
};

const MAX_PROFILE_ID_LENGTH = 64;

function profileIdBase(name: string): string {
  const transliterated = Array.from(name.normalize('NFC').toLowerCase(), character =>
    CYRILLIC_TO_ASCII[character] ?? character
  ).join('');
  const slug = transliterated
    .normalize('NFD')
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^[^a-z]+/, '')
    .replace(/-+$/g, '');
  return (slug || 'router').slice(0, MAX_PROFILE_ID_LENGTH).replace(/-+$/g, '') || 'router';
}

/** Derives a registry-safe, deterministic ID and avoids IDs already in use. */
export function deriveProfileId(name: string, existingIds: Iterable<string> = []): string {
  const occupied = new Set(existingIds);
  const base = profileIdBase(name);
  if (!occupied.has(base)) return base;

  for (let index = 2; ; index += 1) {
    const suffix = `-${index}`;
    const stemLength = MAX_PROFILE_ID_LENGTH - suffix.length;
    const stem = base.slice(0, stemLength).replace(/-+$/g, '') || 'router';
    const candidate = `${stem}${suffix}`;
    if (!occupied.has(candidate)) return candidate;
  }
}

/**
 * Accepts the friendly remote endpoint spellings shown by the onboarding
 * wizard, then returns the strict RCI URL stored in a profile.
 */
export function normalizeWizardEndpoint(raw: string, mode: AuthMode): string {
  const input = raw.trim();
  if (!input) throw new Error('Router endpoint is required');
  if (/[\p{Cc}\p{Cf}]/u.test(input)) throw new Error('Router endpoint must not contain control characters');
  if (mode === 'lan') {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) throw new Error('LAN endpoint must be a bare hostname or IP address');
    let lan: URL;
    try { lan = new URL(`http://${input}`); } catch { throw new Error('LAN endpoint must be a valid hostname or IP address'); }
    if (lan.username || lan.password) throw new Error('LAN endpoint must not contain credentials');
    if (lan.search || lan.hash) throw new Error('LAN endpoint must not contain query or fragment');
    if (!lan.hostname || lan.pathname !== '/') throw new Error('LAN endpoint must not contain a path');
    return input;
  }

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input);
  let url: URL;
  try {
    url = new URL(hasScheme ? input : `https://${input}`);
  } catch {
    throw new Error('Remote endpoint must be a hostname or HTTPS URL');
  }

  if (url.username || url.password) throw new Error('Remote endpoint must not contain credentials');
  if (url.search || url.hash) throw new Error('Remote endpoint must not contain query or fragment');
  if (!url.hostname) throw new Error('Remote endpoint must contain a hostname');

  if (url.protocol === 'http:') {
    const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!hostname.endsWith('.keenetic.pro') && !hostname.endsWith('.netcraze.club')) {
      throw new Error('Remote endpoint must use HTTPS');
    }
    url.protocol = 'https:';
  } else if (url.protocol !== 'https:') {
    throw new Error('Remote endpoint must use HTTPS');
  }

  if (url.pathname === '' || url.pathname === '/' || url.pathname === '/rci') {
    url.pathname = '/rci/';
  }
  if (url.pathname !== '/rci/') throw new Error('Remote endpoint path must be /rci/');

  return url.toString();
}
