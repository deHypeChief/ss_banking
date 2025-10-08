# Use Python 3.13 slim image as base
FROM python:3.13-slim

# Create a non-root user
RUN useradd --create-home --shell /bin/bash app

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies and gunicorn for production
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir flask gunicorn

# Copy the entire project
COPY . .

# Change ownership to non-root user
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Expose port 5000
EXPOSE 5000

# Set environment variables for production
ENV PYTHONPATH=/app
ENV FLASK_APP=web_app.py
ENV FLASK_ENV=production
ENV FLASK_DEBUG=false

# Run the application with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "web_app:app"]