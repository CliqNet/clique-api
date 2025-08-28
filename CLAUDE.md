# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development
```bash
# Install dependencies
pip install -r requirements.txt

# Generate Prisma client
prisma generate

# Run database migrations
prisma db push

# Start development server
python -m app.main
# or
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Start with Docker
docker build -t clique-api .
docker run -p 10000:10000 clique-api
```

### Database
```bash
# Reset database
prisma db push --force-reset

# View database
prisma studio

# Seed database
python prisma/seed.py
```

### Testing
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/api/auth/test_auth.py

# Run tests with coverage
pytest --cov=app

# Run specific test function
pytest tests/api/auth/test_auth.py::test_login_success
```

### Code Quality
```bash
# Format code
black .

# Lint code
ruff check .

# Fix linting issues
ruff check . --fix
```

## Architecture

### Core Structure
- **FastAPI Application**: Main app in `app/main.py` with modular router structure
- **Database**: PostgreSQL with Prisma ORM for type-safe database operations
- **Authentication**: JWT-based with refresh tokens, session management, and role-based access
- **Social Integration**: Multi-platform social media account connection and data synchronization
- **Background Tasks**: Async task management for social data fetching and synchronization

### Key Components

#### Database Layer (`app/db/`, `prisma/`)
- Prisma schema defines comprehensive user, social account, and campaign models
- Multi-user types: Creator, Company, Admin with separate profile tables
- Social account management with token refresh, rate limiting, and sync status tracking
- Role-based permissions system with flexible permission assignments

#### Authentication (`app/api/auth/`, `app/services/auth_service.py`, `app/utils/auth_utils.py`)
- JWT access/refresh token system with configurable expiration
- Session management with device tracking and blacklisting
- Password reset functionality with secure token generation
- Multi-role user types with appropriate profile creation

#### Social Media Integration (`app/api/socials/`)
- OAuth flow handling for multiple platforms (Instagram, Facebook, YouTube, Twitter, TikTok, LinkedIn)
- Token management with automatic refresh and error handling
- Background synchronization of follower counts, engagement metrics
- Rate limiting per platform with quota tracking
- Webhook support for real-time updates

#### API Structure (`app/api/`)
- Modular router design with separated concerns
- Consistent error handling and validation
- WebSocket support for real-time notifications
- Rate limiting middleware

#### Services Layer (`app/services/`)
- `auth_service.py`: Core authentication business logic
- `user_service.py`: User management and profile operations  
- `notification_service.py`: Event-driven notifications
- `websocket_manager.py`: Real-time connection management
- `redis_client.py`: Caching and session storage

### Environment Configuration
The application uses Pydantic settings in `app/core/config.py`:
- Database URLs for primary and direct connections
- JWT secret keys and expiration settings
- CORS origins configuration
- Email/SendGrid settings for notifications
- Rate limiting configuration
- Redis URL for caching

### Testing Strategy
- Comprehensive test setup with pytest and async support
- Prisma client mocking for isolated unit tests
- Test structure mirrors application structure
- FastAPI TestClient for integration testing

### Social Platform Architecture
- `SocialAccount` model tracks connection status, tokens, and metrics per platform
- Platform-specific data fetchers with error handling and retry logic
- Sync scheduler for periodic data updates
- Connection status tracking (CONNECTED, TOKEN_EXPIRED, RATE_LIMITED, etc.)
- Platform configuration for API limits and credentials

### Security Features
- Password hashing with bcrypt
- JWT token blacklisting for secure logout
- Rate limiting to prevent abuse
- Input validation with Pydantic models
- CORS configuration for frontend integration
- Sensitive data encryption for platform secrets