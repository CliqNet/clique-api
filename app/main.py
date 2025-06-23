# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.lib.prisma import prisma
from app.core.config import settings


app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    version="1.0.0"
)

# CORS middleware //settings.ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    # Always attempt to connect on startup
    await prisma.connect()
    # Then check if connected to print the message
    if prisma.is_connected:
        print("✅ Connected to database")
    else:
        print("❌ Failed to connect to database or connection was already established elsewhere.")


@app.on_event("shutdown")
async def shutdown():
    if not prisma.is_connected:
        await prisma.disconnect()
        print("✅ Disconnected from database")
    else:
        print("Database not connected, no need to disconnect.")

app.include_router(router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )