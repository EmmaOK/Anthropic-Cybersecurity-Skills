FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app

# Install dependencies first (layer-cached unless requirements change)
COPY mcp/requirements-http.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy skill library and MCP server
COPY index.json           ./index.json
COPY skills/              ./skills/
COPY mcp/phantom_mcp_server.py   ./mcp/phantom_mcp_server.py
COPY mcp/phantom_http_server.py  ./mcp/phantom_http_server.py
COPY security/kill-switch-phantom-mcp/ ./security/kill-switch-phantom-mcp/

# Non-root user for security
RUN useradd -m -u 1001 phantom
RUN chown -R phantom:phantom /app
USER phantom

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python3", "mcp/phantom_http_server.py"]
