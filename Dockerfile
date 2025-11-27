# Base Python image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY api/ ./api/

# Expose port
EXPOSE 8080

# Run the FastAPI server
CMD ["python", "api/app.py"]
