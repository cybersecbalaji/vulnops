FROM python:3.12-slim

# Security: run as non-root user
RUN addgroup --system vulnops && adduser --system --group vulnops

WORKDIR /app

# Install build dependencies needed for cryptography/bcrypt
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies as root (before switching user)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=vulnops:vulnops . .

USER vulnops

EXPOSE 8000

# Use Uvicorn with Gunicorn-style worker count for production
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
