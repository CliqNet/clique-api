# app/middleware/rate_limit.py
import redis
from fastapi import HTTPException, Request
# from datetime import datetime, timedelta
from app.core.config import settings


redis_client = redis.from_url(settings.REDIS_URL)


async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host

    # Different limits for different endpoints
    if request.url.path in ["/auth/login", "/auth/signup"]:
        limit = 5  # 5 attempts per hour
        window = 3600
    else:
        limit = settings.RATE_LIMIT_REQUESTS
        window = settings.RATE_LIMIT_WINDOW

    key = f"rate_limit:{client_ip}:{request.url.path}"
    current = redis_client.get(key)

    if current is None:
        redis_client.setex(key, window, 1)
    else:
        if int(current) >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        redis_client.incr(key)

    response = await call_next(request)
    return response
