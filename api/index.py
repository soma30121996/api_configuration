from mangum import Mangum

# --- Import the FastAPI instance ---
try:
    from app import app   # if app.py is in project root
except ImportError:
    from .app import app  # if Vercel resolves as module

handler = Mangum(app)
