import os
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Search for .env in current directory and backend directory
root_dir = Path(__file__).resolve().parent.parent.parent
backend_env = root_dir / ".env"
parent_env = root_dir.parent / ".env"

if backend_env.exists():
    load_dotenv(backend_env)
elif parent_env.exists():
    load_dotenv(parent_env)
else:
    load_dotenv()

_supabase_client = None


def is_supabase_configured() -> bool:
    """Check if Supabase credentials exist in environment without exposing secrets."""
    url = os.getenv("SUPABASE_URL", "").strip()
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY") or "").strip()
    return bool(url and key and not url.startswith("https://your-project") and url.startswith("https://"))


def get_supabase_client():
    """
    Safely retrieves the initialized Supabase client.
    Returns None if credentials are not configured or on initialization failure.
    """
    global _supabase_client

    if _supabase_client is not None:
        return _supabase_client

    if not is_supabase_configured():
        return None

    url = os.getenv("SUPABASE_URL", "").strip()
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_ANON_KEY") or "").strip()

    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        return _supabase_client
    except Exception:
        return None


def check_supabase_connection() -> Dict[str, Any]:
    """
    Safely checks Supabase connectivity status without throwing unhandled errors.
    """
    if not is_supabase_configured():
        return {
            "configured": False,
            "status": "unconfigured",
            "message": "Supabase environment variables not set. Running in local standalone mode.",
            "url_set": bool(os.getenv("SUPABASE_URL", "").strip()),
        }

    client = get_supabase_client()
    if client is None:
        return {
            "configured": True,
            "status": "initialization_failed",
            "message": "Failed to initialize Supabase client with provided environment variables.",
            "url_set": True,
        }

    try:
        # Perform lightweight query to check connectivity
        response = client.table("diode_configurations").select("channel_name").limit(1).execute()
        return {
            "configured": True,
            "status": "connected",
            "message": "Supabase database connection verified.",
            "url_set": True,
            "tables_ready": True,
        }
    except Exception as e:
        error_msg = str(e)
        # If table doesn't exist yet, connection is still valid but schema needs to be applied
        return {
            "configured": True,
            "status": "connected_needs_schema" if "relation" in error_msg or "PGRST204" in error_msg or "404" in error_msg or "PGRST" in error_msg else "error",
            "message": f"Connected to Supabase endpoint ({error_msg})",
            "url_set": True,
            "tables_ready": False,
        }
