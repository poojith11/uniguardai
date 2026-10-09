import { createClient, SupabaseClient } from '@supabase/supabase-js';

let _supabaseClient: SupabaseClient | null = null;

/**
 * Checks if Supabase credentials are configured in frontend environment without exposing values.
 */
export function isSupabaseConfigured(): boolean {
  const url = import.meta.env.VITE_SUPABASE_URL;
  const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
  return Boolean(
    url && 
    anonKey && 
    typeof url === 'string' && 
    typeof anonKey === 'string' &&
    !url.includes('your-project') &&
    url.startsWith('https://')
  );
}

/**
 * Lazily retrieves the initialized Supabase client.
 * Returns null gracefully if environment variables are missing.
 */
export function getSupabaseClient(): SupabaseClient | null {
  if (_supabaseClient) {
    return _supabaseClient;
  }

  if (!isSupabaseConfigured()) {
    return null;
  }

  try {
    const url = import.meta.env.VITE_SUPABASE_URL as string;
    const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string;
    _supabaseClient = createClient(url, anonKey, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
      },
    });
    return _supabaseClient;
  } catch (error) {
    console.warn('[UNIGUARD AI] Supabase initialization failed:', error);
    return null;
  }
}

/**
 * Health check utility for verifying client-side Supabase connectivity.
 */
export async function checkSupabaseHealth(): Promise<{
  configured: boolean;
  connected: boolean;
  message: string;
}> {
  if (!isSupabaseConfigured()) {
    return {
      configured: false,
      connected: false,
      message: 'Supabase environment variables (VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY) not configured. Operating in local mode.',
    };
  }

  const client = getSupabaseClient();
  if (!client) {
    return {
      configured: true,
      connected: false,
      message: 'Failed to instantiate Supabase client.',
    };
  }

  try {
    const { error } = await client.from('diode_configurations').select('channel_name').limit(1);
    if (error && error.code !== 'PGRST116') {
      return {
        configured: true,
        connected: false,
        message: `Connected to Supabase endpoint, but table query returned: ${error.message}`,
      };
    }
    return {
      configured: true,
      connected: true,
      message: 'Supabase database connection active and verified.',
    };
  } catch (err) {
    return {
      configured: true,
      connected: false,
      message: `Supabase network check failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
