"""Project detection - fingerprints the uploaded codebase and produces a
structured map of languages, frameworks, package managers, build/start/test
commands, ports, and security-relevant signals. Never assumes a single
language.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

IGNORED_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build", ".next", "target", ".idea", ".vscode", ".tox", ".mypy_cache", ".pytest_cache", "coverage"}

KEY_FILES = [
    "package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json", "npm-shrinkwrap.json",
    "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", "uv.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew", "mvnw",
    "composer.json", "composer.lock", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "Rakefile", "config.ru",
    "*.csproj", "*.sln", "packages.config", "Directory.Build.props",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "manage.py", "app.py", "wsgi.py", "asgi.py", "main.py", "server.js", "app.js", "index.js",
    "next.config.js", "next.config.mjs", "vite.config.ts", "vite.config.js", "nuxt.config.ts",
    "angular.json", "vue.config.js", "svelte.config.js", "remix.config.js",
    "webpack.config.js", "tsconfig.json", ".env", ".env.example", ".env.sample",
    "pytest.ini", "setup.cfg", "tox.ini", "jest.config.js", "jest.config.ts", "vitest.config.ts",
    "playwright.config.ts", "playwright.config.js", "Cargo.toml", "go.work",
]

FRAMEWORK_MARKERS: list[tuple[str, re.Pattern]] = [
    ("express", re.compile(r'"express"\s*:\s*"[^"]+"', re.I)),
    ("nestjs", re.compile(r'"@nestjs/core"\s*:', re.I)),
    ("nextjs", re.compile(r'"next"\s*:\s*"[^"]+"', re.I)),
    ("react", re.compile(r'"react"\s*:\s*"[^"]+"', re.I)),
    ("vue", re.compile(r'"vue"\s*:\s*"[^"]+"', re.I)),
    ("angular", re.compile(r'"@angular/core"\s*:', re.I)),
    ("svelte", re.compile(r'"svelte"\s*:', re.I)),
    ("nuxt", re.compile(r'"nuxt"\s*:', re.I)),
    ("remix", re.compile(r'"@remix-run/\w+"\s*:', re.I)),
    ("vite", re.compile(r'"vite"\s*:', re.I)),
    ("fastify", re.compile(r'"fastify"\s*:', re.I)),
    ("django", re.compile(r'"django|django\s*==|django\s*>=')),
    ("flask", re.compile(r'"flask|flask\s*==|flask\s*>=')),
    ("fastapi", re.compile(r'"fastapi|fastapi\s*==|fastapi\s*>=')),
    ("starlette", re.compile(r'"starlette')),
    ("spring_boot", re.compile(r"spring-boot|org\.springframework\.boot")),
    ("laravel", re.compile(r'"laravel/framework"')),
    ("symfony", re.compile(r'"symfony/' )),
    ("rails", re.compile(r'"rails\s*[,~]') ),
    ("gin", re.compile(r"github\.com/gin-gonic/gin")),
    ("echo", re.compile(r"github\.com/labstack/echo")),
    ("aspnet", re.compile(r"Microsoft\.AspNetCore")),
    ("actix", re.compile(r"actix-web")),
]

AUTH_MARKERS = [
    "bcrypt", "argon2", "passlib", "jwt", "jsonwebtoken", "passport", "session",
    "oauth", "openid", "django.contrib.auth", "flask-login", "devise", "authlib",
    "spring-security", "keycloak", "basic-auth", "Authorization",
]

DB_MARKERS = ["sqlite", "postgres", "postgresql", "mysql", "mongodb", "mongo", "redis", "cassandra", "mariadb", "dynamodb", "psycopg", "sqlalchemy", "mongoose", "prisma", "typeorm", "sequelize", "knex"]

API_FRAMEWORKS = ["fastapi", "flask", "django", "express", "nestjs", "fastify", "spring", "aspnet", "laravel", "rails", "gin", "echo", "actix", "graphql"]


def _read_small(path: Path, max_bytes: int = 256 * 1024) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError:
        return ""


def _walk(root: Path) -> list[Path]:
    out: list[Path] = []
    try:
        for p in root.rglob("*"):
            if p.is_symlink():
                continue
            rel = p.relative_to(root)
            if any(part in IGNORED_DIRS for part in rel.parts):
                continue
            out.append(p)
    except OSError:
        pass
    return out


def _detect_languages(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    ext_map = {
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".py": "python", ".pyw": "python",
        ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
        ".php": "php",
        ".go": "go",
        ".rb": "ruby",
        ".cs": "csharp", ".fs": "fsharp",
        ".rs": "rust",
        ".swift": "swift",
        ".html": "html", ".vue": "vue", ".svelte": "svelte", ".css": "css", ".scss": "scss",
        ".sql": "sql",
        ".sh": "shell", ".bash": "shell", ".zsh": "shell",
        ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml", ".ini": "ini", ".env": "env",
        ".md": "markdown",
    }
    for f in files:
        ext = f.suffix.lower()
        if ext in ext_map:
            counts[ext_map[ext]] = counts.get(ext_map[ext], 0) + 1
        elif f.name in ("Dockerfile", "Makefile", "Procfile", "wsgi.py", "asgi.py", "manage.py", "server.js", "app.js"):
            counts.setdefault("config", counts.get("config", 0))
    # special names
    for f in files:
        if f.name == "Dockerfile":
            counts["docker"] = counts.get("docker", 0) + 1
    return counts


def detect_project(root: Path) -> dict[str, Any]:
    """Full detection pass over an extracted project. Pure and deterministic."""
    files = _walk(root)
    rel_files = [str(f.relative_to(root)) for f in files]
    languages = _detect_languages(files)

    # --- package managers / manifests --------------------------------------
    manifests: dict[str, list[str]] = {}
    if (root / "package.json").exists():
        manifests["npm"] = ["package.json"]
        if (root / "package-lock.json").exists():
            manifests["npm-lock"] = ["package-lock.json"]
        if (root / "pnpm-lock.yaml").exists():
            manifests["pnpm"] = ["pnpm-lock.yaml"]
        if (root / "yarn.lock").exists():
            manifests["yarn"] = ["yarn.lock"]
    if (root / "requirements.txt").exists():
        manifests["pip"] = ["requirements.txt"]
    if (root / "pyproject.toml").exists():
        content = _read_small(root / "pyproject.toml")
        if "[tool.poetry]" in content:
            manifests["poetry"] = ["pyproject.toml"]
        else:
            manifests["pip"] = ["pyproject.toml"]
    if (root / "Pipfile").exists():
        manifests["pipenv"] = ["Pipfile"]
    if (root / "uv.lock").exists():
        manifests["uv"] = ["uv.lock"]
    if (root / "pom.xml").exists():
        manifests["maven"] = ["pom.xml"]
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        manifests["gradle"] = ["build.gradle", "build.gradle.kts"]
    if (root / "composer.json").exists():
        manifests["composer"] = ["composer.json"]
    if (root / "go.mod").exists():
        manifests["go"] = ["go.mod"]
    if (root / "Gemfile").exists():
        manifests["bundler"] = ["Gemfile"]
    if (root / "Cargo.toml").exists():
        manifests["cargo"] = ["Cargo.toml"]
    if list(root.glob("*.csproj")) or list(root.glob("*.sln")):
        manifests["dotnet"] = ["*.csproj"]

    # --- frameworks ----------------------------------------------------------
    frameworks: list[str] = []
    search_text = ""
    for name in ("package.json", "pyproject.toml", "requirements.txt", "Pipfile", "composer.json", "pom.xml", "go.mod", "Gemfile"):
        p = root / name
        if p.exists():
            search_text += "\n" + _read_small(p)
    for fname, pattern in FRAMEWORK_MARKERS:
        if pattern.search(search_text):
            frameworks.append(fname)
    if (root / "manage.py").exists():
        frameworks.append("django")
    if (root / "app.py").exists() and "flask" in search_text:
        frameworks.append("flask")
    for f in files:
        if f.suffix in (".py",) and f.name in ("main.py", "app.py", "server.py"):
            content = _read_small(f)
            if "FastAPI" in content or "fastapi" in content:
                frameworks.append("fastapi")
            if "Flask" in content:
                frameworks.append("flask")
    # container
    has_dockerfile = any(f.name == "Dockerfile" for f in files)
    compose_files = [f for f in files if f.name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")]
    container: dict[str, Any] = {"dockerfile": has_dockerfile, "compose": [f.name for f in compose_files]}

    # --- build / start / test commands ----------------------------------------
    commands = {"build": None, "start": None, "test": None, "install": None}
    pkg = None
    pkg_path = root / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pkg = {}
    if pkg:
        scripts = pkg.get("scripts", {}) or {}
        commands["build"] = scripts.get("build") or scripts.get("compile") or None
        commands["start"] = scripts.get("start") or scripts.get("dev") or None
        commands["test"] = scripts.get("test") or None
        commands["install"] = "npm install"
    elif (root / "pyproject.toml").exists():
        commands["install"] = "pip install -e ."
        commands["build"] = None
        commands["test"] = "pytest" if (root / "pytest.ini").exists() or "pytest" in _read_small(root / "pyproject.toml") else None
    elif (root / "requirements.txt").exists():
        commands["install"] = "pip install -r requirements.txt"
        commands["test"] = "pytest" if (root / "pytest.ini").exists() or any("pytest" in _read_small(f) for f in files if f.name == "requirements.txt") else None
    elif (root / "pom.xml").exists():
        commands["install"] = "mvn dependency:resolve"
        commands["build"] = "mvn -q -DskipTests package"
        commands["test"] = "mvn test"
    elif (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        commands["install"] = "gradle dependencies"
        commands["build"] = "gradle build"
        commands["test"] = "gradle test"
    elif (root / "go.mod").exists():
        commands["install"] = "go mod download"
        commands["build"] = "go build ./..."
        commands["test"] = "go test ./..."
    elif (root / "composer.json").exists():
        commands["install"] = "composer install"
        commands["test"] = "vendor/bin/phpunit" if (root / "phpunit.xml").exists() else None
    elif (root / "Gemfile").exists():
        commands["install"] = "bundle install"
        commands["test"] = "bundle exec rspec" if (root / "spec").exists() else "bundle exec rails test"

    # --- entrypoints -----------------------------------------------------------
    entrypoints: list[str] = []
    if pkg and pkg.get("main"):
        entrypoints.append(str(pkg["main"]))
    for cand in ("main.py", "app.py", "server.py", "manage.py", "wsgi.py", "asgi.py", "index.js", "server.js", "app.js", "src/index.js", "src/main.ts", "src/main.tsx"):
        if (root / cand).exists():
            entrypoints.append(cand)
    if pkg and pkg.get("bin"):
        if isinstance(pkg["bin"], dict):
            entrypoints.extend(list(pkg["bin"].values()))
        else:
            entrypoints.append(str(pkg["bin"]))

    # --- ports / config / env ---------------------------------------------------
    ports: set[int] = set()
    for f in files:
        if f.suffix not in (".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yml", ".yaml", ".json", ".go", ".rb", ".php", ".java"):
            continue
        if f.name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum"):
            continue
        content = _read_small(f)
        for m in re.finditer(r"(?:PORT|port)\s*[=:]\s*['\"]?(\d{2,5})", content):
            p = int(m.group(1))
            if 1024 <= p <= 65535 and p not in (8000, 5173, 5432, 3306, 6379, 27017):
                ports.add(p)
        for m in re.finditer(r"listen\(\s*(\d{2,5})", content):
            p = int(m.group(1))
            if 1024 <= p <= 65535:
                ports.add(p)
    if "express" in frameworks and not ports:
        ports.add(3000)
    if "fastapi" in frameworks or "flask" in frameworks:
        ports.add(8000)
    if "django" in frameworks:
        ports.add(8000)

    # --- env vars ---------------------------------------------------------------
    env_vars: set[str] = set()
    for f in files:
        if f.name.startswith(".env") or f.suffix == ".env":
            for line in _read_small(f).splitlines():
                m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                if m:
                    env_vars.add(m.group(1))
    env_files = [str(f.relative_to(root)) for f in files if f.name.startswith(".env")]

    # --- security signals ---------------------------------------------------------
    all_text = " ".join(_read_small(f) for f in files if f.suffix in (".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".java", ".env") and f.name not in ("package-lock.json", "yarn.lock"))
    auth_indicators = [m for m in AUTH_MARKERS if m.lower() in all_text.lower()]
    db_deps = [m for m in DB_MARKERS if m.lower() in all_text.lower()]
    api_frameworks = [f for f in API_FRAMEWORKS if f in frameworks or f in all_text.lower()[:200_000]]

    frontend_indicators = any(f.suffix in (".tsx", ".jsx", ".vue", ".svelte") or f.name.startswith("next.config") for f in files)
    backend_indicators = any(f.suffix == ".py" and f.name in ("main.py", "app.py", "server.py") for f in files) or "express" in frameworks or "fastapi" in frameworks or "django" in frameworks or "flask" in frameworks or "nestjs" in frameworks

    project_type = "unknown"
    if "nextjs" in frameworks or frontend_indicators:
        project_type = "webapp"
    if backend_indicators:
        project_type = "webapp" if project_type == "webapp" else ("webapp" if backend_indicators else project_type)
    if not backend_indicators and not frontend_indicators:
        if "python" in languages:
            project_type = "python"
        elif "javascript" in languages or "typescript" in languages:
            project_type = "javascript"
        elif "java" in languages:
            project_type = "java"
        elif "go" in languages:
            project_type = "go"
        elif "php" in languages:
            project_type = "php"
        elif "ruby" in languages:
            project_type = "ruby"
        elif "csharp" in languages:
            project_type = "dotnet"

    return {
        "project_type": project_type,
        "languages": dict(sorted(languages.items(), key=lambda kv: -kv[1])),
        "frameworks": sorted(set(frameworks)),
        "package_managers": manifests,
        "commands": commands,
        "entrypoints": entrypoints,
        "ports": sorted(ports),
        "env_vars": sorted(env_vars),
        "env_files": env_files,
        "auth_indicators": sorted(set(auth_indicators)),
        "database_dependencies": sorted(set(db_deps)),
        "api_frameworks": sorted(set(api_frameworks)),
        "frontend_present": bool(frontend_indicators),
        "backend_present": bool(backend_indicators),
        "container": container,
        "file_count": len(files),
        "size_bytes": sum(p.stat().st_size for p in files if p.is_file()),
        "has_tests": bool(commands.get("test")) or any("test" in str(f).lower() for f in files if f.suffix in (".py", ".js", ".ts")),
    }
