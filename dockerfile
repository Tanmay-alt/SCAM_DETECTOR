# Dockerfile (Updated)

# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# --- ADD THIS NEW LINE ---
# Download the spaCy English language model
RUN python -m spacy download en_core_web_sm

# Copy the rest of the application's code into the container
COPY . .

# Make the boot script executable
RUN chmod +x boot.sh

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Set environment variable for Flask
ENV FLASK_APP=app.py

# Run the boot script when the container launches
CMD ["./boot.sh"]