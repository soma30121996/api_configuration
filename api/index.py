from fastapi import FastAPI
from mangum import Mangum

app = FastAPI()

@app.get("/")
def home():
    return {"message": "FastAPI deployed successfully on Vercel 🎉"}

handler = Mangum(app)
