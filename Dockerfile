# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (opencv needs these)
RUN apt-get update && apt-get install -y \
    gcc \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p data static/exports static/qrcodes && \
    chmod -R 755 static/exports static/qrcodes

# Create a non-root user for security
RUN useradd -m -u 1000 flaskuser && \
    chown -R flaskuser:flaskuser /app

# Switch to non-root user
USER flaskuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Run the application with Gunicorn
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 4 --threads 2 --timeout 60 --access-logfile - --error-logfile -
