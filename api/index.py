from app import app
from mangum import Mangum

# Attach handler so Vercel can execute FastAPI
handler = Mangum(app)
