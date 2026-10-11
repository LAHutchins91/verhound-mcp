import type { Ecosystem } from "../config.js";

/**
 * Original, hand-curated list of widely used package names per ecosystem.
 * Used only for look-alike flags in verify_package_exists. It is not a
 * ranking and makes no statement about any package.
 */
export const POPULAR: Partial<Record<Ecosystem, readonly string[]>> = {
  npm: [
    "react", "react-dom", "next", "vue", "angular", "svelte", "express", "koa", "fastify", "hapi",
    "lodash", "underscore", "axios", "node-fetch", "request", "moment", "dayjs", "date-fns", "luxon",
    "chalk", "commander", "yargs", "inquirer", "debug", "dotenv", "uuid", "nanoid", "classnames",
    "typescript", "webpack", "rollup", "vite", "esbuild", "babel-core", "eslint", "prettier", "jest",
    "mocha", "chai", "vitest", "cypress", "playwright", "puppeteer", "redux", "mobx", "zustand",
    "jquery", "bootstrap", "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
    "mongoose", "sequelize", "prisma", "knex", "pg", "mysql", "mysql2", "redis", "ioredis", "sqlite3",
    "socket.io", "ws", "graphql", "apollo-server", "body-parser", "cors", "helmet", "morgan", "multer",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "cookie-parser", "nodemon", "concurrently",
    "rimraf", "glob", "minimist", "semver", "fs-extra", "mkdirp", "async", "bluebird", "rxjs",
    "immer", "zod", "yup", "joi", "ajv", "validator", "qs", "cheerio", "marked", "highlight.js",
    "three", "d3", "chart.js", "electron", "react-router", "react-router-dom", "nuxt", "gatsby",
    "openai", "stripe", "aws-sdk", "firebase", "colors", "cross-env", "core-js", "tslib", "left-pad"
  ],
  pypi: [
    "requests", "urllib3", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "scikit-learn",
    "tensorflow", "torch", "keras", "flask", "django", "fastapi", "uvicorn", "gunicorn", "starlette",
    "pydantic", "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql", "redis", "celery",
    "boto3", "botocore", "s3transfer", "awscli", "google-cloud-storage", "azure-storage-blob",
    "pytest", "tox", "nose", "coverage", "mock", "black", "flake8", "pylint", "mypy", "isort", "ruff",
    "setuptools", "wheel", "pip", "virtualenv", "poetry", "twine", "six", "attrs", "click", "rich",
    "typer", "jinja2", "markupsafe", "werkzeug", "itsdangerous", "pyyaml", "toml", "tomli",
    "python-dateutil", "pytz", "certifi", "idna", "charset-normalizer", "chardet", "cryptography",
    "pyopenssl", "paramiko", "beautifulsoup4", "lxml", "scrapy", "selenium", "pillow", "opencv-python",
    "httpx", "aiohttp", "websockets", "grpcio", "protobuf", "openai", "anthropic", "langchain",
    "transformers", "tqdm", "colorama", "pyjwt", "python-dotenv", "jsonschema", "simplejson",
    "packaging", "docutils", "sphinx", "ipython", "jupyter", "notebook", "networkx", "sympy", "stripe"
  ],
  cargo: ["serde", "serde_json", "tokio", "rand", "clap", "reqwest", "anyhow", "thiserror", "regex", "chrono", "log", "hyper", "axum", "syn", "quote"],
  nuget: ["Newtonsoft.Json", "Serilog", "AutoMapper", "Dapper", "Moq", "xunit", "NUnit", "Polly", "MediatR", "FluentValidation"],
  go: [],
  maven: []
};
