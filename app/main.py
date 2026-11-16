import logging
import os
from urllib.parse import unquote, urlsplit

import boto3
import httpx
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env_file(path: str) -> dict:
    """Parse a KEY=VALUE env file; comments and blank lines are ignored."""
    values = {}
    try:
        with open(path, encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip()
                if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
                    value = value[1:-1]
                values[key.strip()] = value
    except OSError:
        pass
    return values


# Precedence: process environment > .env > .env.example > built-in defaults.
ENV_FILE = {
    **load_env_file(os.path.join(BASE_DIR, ".env.example")),
    **load_env_file(os.path.join(BASE_DIR, ".env")),
}


def env(name: str, default: str = "") -> str:
    if name in os.environ:
        return os.environ[name]
    return ENV_FILE.get(name, default)


logging.basicConfig(level=env("LOG_LEVEL", "INFO"))
log = logging.getLogger("minio-cerbos-gateway")


def parse_bucket_kinds(raw: str) -> dict:
    """Parse "bucket=kind,bucket2=kind2" into a mapping."""
    mapping = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ValueError(f"Invalid CERBOS_BUCKET_KINDS entry: {item!r}")
        bucket, kind = item.split("=", 1)
        bucket = bucket.strip()
        kind = kind.strip()
        if not bucket or not kind:
            raise ValueError(f"Invalid CERBOS_BUCKET_KINDS entry: {item!r}")
        mapping[bucket] = kind
    return mapping


def resolve_root_path() -> str:
    """Path prefix the gateway is mounted under, e.g. "share/s3" -> "/share/s3"."""
    raw = env("root_path", "/share/s3").strip().strip("/")
    return f"/{raw}" if raw else ""


CERBOS_URL = env("CERBOS_URL", "http://cerbos:3592").rstrip("/")
CERBOS_RESOURCE_KIND = env("CERBOS_RESOURCE_KIND", "minio_object")
BUCKET_KINDS = parse_bucket_kinds(env("CERBOS_BUCKET_KINDS", ""))
MINIO_ENDPOINT = env("MINIO_ENDPOINT", "https://oss.feg.cn")
MINIO_REGION = env("MINIO_REGION", "us-east-1")
ROOT_PATH = resolve_root_path()


def resolve_use_ssl(endpoint: str) -> bool:
    """Explicit MINIO_SECURE wins; otherwise follow the endpoint URL scheme."""
    explicit = env("MINIO_SECURE", "")
    if explicit and explicit.strip():
        return explicit.strip().lower() == "true"
    return urlsplit(endpoint).scheme.lower() == "https"


MINIO_SECURE = resolve_use_ssl(MINIO_ENDPOINT)


def create_s3_client():
    """Build the MinIO client.

    When MINIO_ACCESS_KEY and MINIO_SECRET_KEY are both set the client signs
    requests with them. Otherwise the client issues unsigned (anonymous)
    requests and MinIO decides access with its own bucket policy.
    """
    access_key = env("MINIO_ACCESS_KEY", "").strip()
    secret_key = env("MINIO_SECRET_KEY", "").strip()

    common = {
        "endpoint_url": MINIO_ENDPOINT,
        "region_name": MINIO_REGION,
        "use_ssl": MINIO_SECURE,
    }

    if access_key and secret_key:
        return boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            **common,
        )

    if access_key or secret_key:
        log.warning(
            "Only one of MINIO_ACCESS_KEY/MINIO_SECRET_KEY is set; "
            "falling back to anonymous MinIO access"
        )

    # Anonymous mode: never let botocore look up ambient credentials (IMDS).
    os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
    log.info("MinIO credentials not configured; using anonymous (unsigned) access")
    return boto3.client("s3", config=Config(signature_version=UNSIGNED), **common)


s3 = create_s3_client()

app = FastAPI(
    title="MinIO Cerbos Authorization Gateway",
    version="1.0.0",
    root_path=ROOT_PATH,
)


@app.on_event("startup")
async def startup():
    app.state.cerbos = httpx.AsyncClient(base_url=CERBOS_URL, timeout=5.0)


@app.on_event("shutdown")
async def shutdown():
    await app.state.cerbos.aclose()


def client_ip(request: Request) -> str:
    """Resolve the client IP used in policy conditions.

    The gateway is expected to run behind a trusted reverse proxy that
    overwrites X-Forwarded-For (nginx: `proxy_set_header X-Forwarded-For
    $remote_addr;`). The TCP peer address is used as a fallback.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    peer = request.client
    return peer.host if peer else ""


def principal_from_request(request: Request) -> dict:
    """Identity headers must be overwritten by a trusted authentication proxy."""
    user_id = request.headers.get("X-Auth-User")
    roles_header = request.headers.get("X-Auth-Roles", "")
    org = request.headers.get("X-Auth-Org", "")
    path_prefix = request.headers.get("X-Auth-Path-Prefix", "")
    ip = client_ip(request)

    if not user_id:
        return {
            "id": "anonymous",
            "roles": ["anonymous"],
            "attr": {"org": "public", "ip": ip},
        }

    roles = [x.strip() for x in roles_header.split(",") if x.strip()]
    if not roles:
        roles = ["user"]

    return {
        "id": user_id,
        "roles": roles,
        "attr": {
            "org": org or "default",
            "path_prefix": path_prefix,
            "ip": ip,
        },
    }


def validate_bucket_and_key(bucket: str, key: str):
    # S3 bucket names cannot contain slash; reject malformed paths and traversal.
    if not bucket or bucket in {".", ".."} or "/" in bucket or "\\" in bucket:
        raise HTTPException(status_code=400, detail="Invalid bucket")
    if not key or key.startswith("/") or "\\" in key or "\x00" in key:
        raise HTTPException(status_code=400, detail="Invalid object key")
    if any(part in {".", ".."} for part in key.split("/")):
        raise HTTPException(status_code=400, detail="Invalid object key")


def resource_kind_for_bucket(bucket: str) -> str:
    """Dedicated policy kinds are looked up per bucket; others use the default."""
    return BUCKET_KINDS.get(bucket, CERBOS_RESOURCE_KIND)


async def authorize(principal: dict, bucket: str, key: str, action: str) -> bool:
    payload = {
        "principal": principal,
        "resources": [{
            "resource": {
                "kind": resource_kind_for_bucket(bucket),
                "id": f"{bucket}/{key}",
                "attr": {"bucket": bucket, "key": key},
            },
            "actions": [action],
        }],
    }
    try:
        response = await app.state.cerbos.post(
            "/api/check/resources", json=payload
        )
        response.raise_for_status()
        result = response.json()["results"][0]
        return result.get("actions", {}).get(action) == "EFFECT_ALLOW"
    except (httpx.HTTPError, KeyError, IndexError, ValueError):
        log.exception("Cerbos check failed; denying request")
        raise HTTPException(
            status_code=503, detail="Authorization service unavailable"
        )


@app.get("/healthz")
async def health():
    return {"status": "ok"}


@app.api_route("/{bucket}/{object_key:path}", methods=["GET", "HEAD"])
async def object_proxy(bucket: str, object_key: str, request: Request):
    # FastAPI has already URL-decoded the path. Reject encoded traversal too.
    decoded_key = unquote(object_key)
    validate_bucket_and_key(bucket, decoded_key)

    principal = principal_from_request(request)
    action = "read"
    if not await authorize(principal, bucket, decoded_key, action):
        raise HTTPException(status_code=403, detail="Access denied by Cerbos")

    try:
        if request.method == "HEAD":
            obj = s3.head_object(Bucket=bucket, Key=decoded_key)
            headers = {
                "Content-Type": obj.get("ContentType", "application/octet-stream"),
                "Content-Length": str(obj["ContentLength"]),
                "Cache-Control": "private, no-store",
            }
            if obj.get("ETag"):
                headers["ETag"] = obj["ETag"]
            return Response(status_code=200, headers=headers)

        params = {"Bucket": bucket, "Key": decoded_key}
        range_header = request.headers.get("range")
        if range_header:
            params["Range"] = range_header
        obj = s3.get_object(**params)

        headers = {
            "Content-Type": obj.get("ContentType", "application/octet-stream"),
            "Cache-Control": "private, no-store",
            "Accept-Ranges": "bytes",
        }
        for source, target in (
            ("ContentLength", "Content-Length"),
            ("ETag", "ETag"),
            ("ContentRange", "Content-Range"),
            ("LastModified", "Last-Modified"),
        ):
            value = obj.get(source)
            if value is not None:
                headers[target] = str(value)

        def body_iterator():
            body = obj["Body"]
            try:
                while True:
                    chunk = body.read(256 * 1024)
                    if not chunk:
                        break
                    yield chunk
            finally:
                body.close()

        status = 206 if obj.get("ContentRange") else 200
        return StreamingResponse(
            body_iterator(),
            status_code=status,
            headers=headers,
            media_type=obj.get("ContentType", "application/octet-stream"),
        )

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "NoSuchBucket", "404", "NotFound"}:
            raise HTTPException(status_code=404, detail="Object not found")
        if code in {"AccessDenied", "403"}:
            raise HTTPException(
                status_code=403, detail="Access denied by storage backend"
            )
        log.exception("MinIO request failed")
        raise HTTPException(status_code=502, detail="Storage backend error")
