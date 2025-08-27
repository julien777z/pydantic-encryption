def _try_import(name: str):
    try:
        return __import__(__name__ + "." + name, fromlist=[None])
    except Exception:
        return None


argon2 = _try_import("argon2")

__all__ = [n for n, m in (("argon2", argon2),) if m]
