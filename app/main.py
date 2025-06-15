from fastapi import FastAPI
from app.api.routes import router
from app.lib.prisma import prisma

app = FastAPI()

@app.on_event("startup")
async def startup():
    await prisma.connect()

@app.on_event("shutdown")
async def shutdown():
    await prisma.disconnect()

app.include_router(router)