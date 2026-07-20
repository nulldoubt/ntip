export const THEME_PREFERENCE_STORAGE_KEY = "ntip.theme";

export const THEME_PREFERENCES = ["system", "light", "dark"] as const;
export type ThemePreference = (typeof THEME_PREFERENCES)[number];
export type ResolvedTheme = Exclude<ThemePreference, "system">;

export interface ThemePreferenceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export function parseThemePreference(value: unknown): ThemePreference {
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

export function readThemePreference(
  storage: ThemePreferenceStorage,
  storageKey = THEME_PREFERENCE_STORAGE_KEY,
): ThemePreference {
  try {
    return parseThemePreference(storage.getItem(storageKey));
  } catch {
    return "system";
  }
}

export function persistThemePreference(
  storage: ThemePreferenceStorage,
  preference: ThemePreference,
  storageKey = THEME_PREFERENCE_STORAGE_KEY,
): boolean {
  try {
    storage.setItem(storageKey, preference);
    return true;
  } catch {
    return false;
  }
}

export function resolveThemePreference(preference: ThemePreference, systemPrefersDark: boolean): ResolvedTheme {
  return preference === "system" ? (systemPrefersDark ? "dark" : "light") : preference;
}
