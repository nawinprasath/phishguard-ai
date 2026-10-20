# Use official lightweight Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files into container
COPY . .

# Hugging Face Spaces runs on port 7860
EXPOSE 7860
ENV PORT=7860

# Run Flask application via Gunicorn production server
CMD ["gunicorn", "-b", "0.0.0.0:7860", "--workers=2", "--timeout=120", "app:app"]
