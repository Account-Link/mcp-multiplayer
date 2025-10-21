FROM python:3.11-slim
WORKDIR /app

# Copy and install dependencies first for better caching
COPY requirements.txt .
RUN pip install -r requirements.txt

RUN useradd -m -u 1000 botuser && \
    chown -R botuser:botuser /app && \
    mkdir -p /tmp/bot_workspace /app/data && \
    chown botuser:botuser /tmp/bot_workspace /app/data

USER botuser

# Copy only the source files needed for the application
COPY *.py .
COPY bots/ ./bots/

EXPOSE 8100
CMD ["python", "start_servers.py"]
