# Development image for Codespaces: Python 3.14 on Debian 13 (trixie), plus uv.
# Node, Docker and the GitHub CLI come from the features in devcontainer.json.
# Dependabot proposes new versions of both images (see .github/dependabot.yml).
#
# The build runs as root so the features can install. devcontainer.json logs you in
# as the image's non-root user, vscode.
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv
FROM mcr.microsoft.com/devcontainers/python:3-3.14-trixie
COPY --from=uv /uv /uvx /bin/
