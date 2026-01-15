# ---------- Build stage ----------
FROM python:3.13-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install build tools and dev libs
RUN apk update && apk add --no-cache \
    build-base \
    gcc \
    g++ \
    libffi-dev \
    libpq \
    openssl-dev \
    mariadb-dev \
    git \
    curl

COPY requirements.txt .

# Install Python deps to a temp location
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt

# ---------- Final stage ----------
FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy the application code
COPY . .

# Create a non-root user (Alpine-style)
RUN adduser -D -h /home/flaskuser flaskuser

# Create upload directory and give ownership to flaskuser
RUN mkdir -p /app/uploads && chown -R flaskuser /app

# Switch to non-root user
USER flaskuser

EXPOSE 5000

# Start the app with Gunicorn
CMD ["python run.py"]
