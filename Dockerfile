FROM python:3.13-slim

WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the rest of the application
COPY . .

# Generate Prisma client and fetch binaries
RUN prisma generate && prisma py fetch

# Expose the port
EXPOSE 10000

# Start the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "10000"]