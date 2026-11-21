FROM python:3.11-slim

LABEL maintainer="ActiveDefenseIR"
LABEL description="Web honeypot — fake vulnerable web app for trapping SQL injection attackers"

# Create log directory
RUN mkdir -p /var/log/honeypot

# Copy the honeypot server
COPY honeypot_server.py /opt/honeypot/honeypot_server.py

WORKDIR /opt/honeypot

# Expose the default honeypot port
EXPOSE 8080

# Environment variables (overridden at runtime by the orchestrator)
ENV HONEYPOT_PORT=8080
ENV HONEYPOT_LOG_DIR=/var/log/honeypot
ENV HONEYPOT_ID=web-unknown

CMD ["python", "-u", "honeypot_server.py"]
