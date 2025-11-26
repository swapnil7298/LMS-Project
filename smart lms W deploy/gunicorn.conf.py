# gunicorn.conf.py
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:" + os.getenv("PORT", "8080")
backlog = 2048

# Worker processes
workers = 1  # Start with 1 worker on Railway
worker_class = "sync"
worker_connections = 1000
timeout = 1200  # Increased timeout to 120 seconds
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process naming
proc_name = "intellilearn"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Maximum requests per worker before restart (helps with memory leaks)
max_requests = 10000
max_requests_jitter = 1000

# Preload app for faster worker startup
preload_app = True