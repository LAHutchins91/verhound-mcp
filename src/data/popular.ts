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
  cargo: [
    "serde", "serde_json", "tokio", "rand", "clap", "reqwest", "anyhow", "thiserror", "regex", "chrono",
    "log", "hyper", "axum", "syn", "quote", "libc", "bytes", "futures", "tracing", "once_cell",
    "lazy_static", "base64", "uuid", "url", "toml", "diesel", "sqlx", "actix-web", "warp", "tempfile",
    "walkdir", "proc-macro2", "rustls", "native-tls", "async-trait", "indexmap", "itertools", "semver",
    "env_logger", "smallvec", "hashbrown", "tokio-util", "openssl"
  ],
  nuget: [
    "Newtonsoft.Json", "Serilog", "AutoMapper", "Dapper", "Moq", "xunit", "NUnit", "Polly", "MediatR", "FluentValidation",
    "Microsoft.EntityFrameworkCore", "Npgsql", "StackExchange.Redis", "Swashbuckle.AspNetCore", "System.Text.Json",
    "NLog", "RestSharp", "Hangfire.Core", "MassTransit", "Humanizer", "CsvHelper", "YamlDotNet",
    "SixLabors.ImageSharp", "SkiaSharp", "AWSSDK.S3", "Azure.Storage.Blobs", "Quartz", "Flurl.Http", "ClosedXML"
  ],
  go: [
    "github.com/gin-gonic/gin", "github.com/stretchr/testify", "github.com/sirupsen/logrus", "github.com/spf13/cobra",
    "github.com/spf13/viper", "github.com/gorilla/mux", "github.com/gorilla/websocket", "github.com/labstack/echo",
    "github.com/go-chi/chi", "go.uber.org/zap", "google.golang.org/grpc", "google.golang.org/protobuf",
    "golang.org/x/crypto", "golang.org/x/sync", "golang.org/x/net", "golang.org/x/sys",
    "github.com/prometheus/client_golang", "github.com/pkg/errors", "github.com/joho/godotenv",
    "github.com/google/uuid", "github.com/rs/zerolog", "github.com/jackc/pgx", "github.com/lib/pq",
    "github.com/go-sql-driver/mysql", "github.com/redis/go-redis", "gorm.io/gorm", "github.com/aws/aws-sdk-go",
    "github.com/golang-jwt/jwt", "k8s.io/client-go", "k8s.io/apimachinery", "go.opentelemetry.io/otel",
    "github.com/nats-io/nats.go", "github.com/segmentio/kafka-go", "github.com/fsnotify/fsnotify",
    "github.com/mitchellh/mapstructure", "github.com/valyala/fasthttp", "github.com/gofiber/fiber"
  ],
  maven: [
    "org.springframework.boot:spring-boot-starter", "org.springframework:spring-core", "org.springframework:spring-context",
    "org.springframework:spring-web", "com.google.guava:guava", "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
    "org.apache.logging.log4j:log4j-core", "junit:junit", "org.junit.jupiter:junit-jupiter-api", "org.mockito:mockito-core",
    "com.fasterxml.jackson.core:jackson-databind", "com.google.code.gson:gson", "org.apache.commons:commons-lang3",
    "commons-io:commons-io", "com.squareup.okhttp3:okhttp", "org.postgresql:postgresql", "com.mysql:mysql-connector-j",
    "org.projectlombok:lombok", "io.netty:netty-all", "com.google.protobuf:protobuf-java", "org.apache.kafka:kafka-clients",
    "org.apache.tomcat.embed:tomcat-embed-core", "org.assertj:assertj-core", "com.h2database:h2", "redis.clients:jedis",
    "org.yaml:snakeyaml", "org.flywaydb:flyway-core", "io.jsonwebtoken:jjwt-api", "org.bouncycastle:bcprov-jdk18on"
  ],
  rubygems: [
    "rails", "railties", "activerecord", "activesupport", "actionpack", "rake", "bundler", "nokogiri", "puma", "rack",
    "sinatra", "devise", "sidekiq", "redis", "pg", "mysql2", "faraday", "httparty", "bcrypt", "jwt",
    "dotenv", "rspec", "minitest", "rubocop", "pry", "bootsnap", "pundit", "aws-sdk-s3", "mail", "zeitwerk",
    "thor", "concurrent-ruby", "i18n", "connection_pool", "selenium-webdriver", "capybara", "factory_bot", "faker"
  ],
  composer: [
    "symfony/console", "symfony/http-foundation", "symfony/framework-bundle", "laravel/framework", "guzzlehttp/guzzle",
    "monolog/monolog", "nesbot/carbon", "doctrine/orm", "doctrine/dbal", "phpunit/phpunit", "vlucas/phpdotenv",
    "league/flysystem", "predis/predis", "ramsey/uuid", "firebase/php-jwt", "nikic/php-parser", "twig/twig",
    "psr/log", "psr/http-message", "phpmailer/phpmailer", "stripe/stripe-php", "aws/aws-sdk-php",
    "composer/semver", "brick/math", "filp/whoops", "psy/psysh", "erusev/parsedown"
  ]
};
