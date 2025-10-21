# Dstack deployment

Deploy MCP Multiplayer to Phala's dstack TEE platform with OAuth 2.1 authentication.

## Architecture
```
External HTTPS → dstack-gateway → OAuth Proxy (port 8100) → MCP Server (port 8201)
```

## Key configuration

Environment variables:
- `USE_SSL=false` - dstack-gateway handles HTTPS termination
- `DOMAIN=<app-id>-8100.dstack-prod5.phala.network` - **CRITICAL**: Must set to actual domain
- `PROXY_HOST=0.0.0.0` - bind to all interfaces in container
- `MCP_HOST=127.0.0.1` - internal MCP server binding
- `PROXY_PORT=8100` - OAuth proxy port
- `MCP_PORT=8201` - MCP server port

Files:
- `docker-compose.yml` - development with local build
- `docker-compose-deploy.yml` - production with SHA256-pinned image
- `start_servers.py` - service orchestrator

## Deployment

Build and push image:
```bash
docker build -t mcp-multiplayer .
docker tag mcp-multiplayer YOUR_REGISTRY/mcp-multiplayer
docker push YOUR_REGISTRY/mcp-multiplayer
docker images --digests YOUR_REGISTRY/mcp-multiplayer
```

Update `docker-compose-deploy.yml` with registry, SHA256 hash, and **actual domain**, then deploy:
```bash
phala deploy docker-compose-deploy.yml --node-id 3
```

Verify deployment:
```bash
curl https://YOUR_URL/.well-known/oauth-authorization-server
```

## Claude MCP Client Compatibility

**OAuth URL Fix**: The service automatically detects reverse proxy deployment and generates correct HTTPS URLs for OAuth endpoints, ensuring Claude's OAuth client can authenticate successfully.

**URL Pattern**: Deployed apps are accessible at:
```
https://<app-id>-8100.dstack-prod5.phala.network
```

**Critical Setup**: Set `DOMAIN` environment variable to the actual dstack domain, not `localhost`. The OAuth proxy will automatically generate HTTPS URLs for external access while maintaining internal HTTP communication.

## Notes

- Only port 8100 (OAuth proxy) exposed externally
- MCP server runs on port 8201 internally
- Dstack provides HTTPS termination, no SSL certificates needed inside container
- OAuth endpoints automatically return HTTPS URLs when `DOMAIN` is set to real domain
- Compatible with Claude's OAuth 2.1 security requirements
- Based on successful deployment pattern from ambient_mcp project

## Persistence

- Named volume `mcp-data:/app/data` for persistent storage across container restarts
- Container runs as `botuser` (uid 1000) - `/app/data` directory must be owned by botuser
- Dockerfile creates `/app/data` with correct ownership before switching to non-root user
- OAuth tokens and channel state persist in volume