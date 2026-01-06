# Build stage
FROM python:3.13.3-alpine AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app


# Install dependencies with cache mount for pip
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.13.3-alpine

WORKDIR /app

# Copy only what’s needed
COPY --from=builder /install /usr/local
COPY . .

# Add non-root user
RUN adduser --disabled-password --gecos '' flaskuser
USER flaskuser

CMD ["python", "run.py"]
