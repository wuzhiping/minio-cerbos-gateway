import logging
import os
from urllib.parse import unquote

import boto3
import httpx
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("minio-cerbos-gateway")

CERBOS_URL = os.getenv("CERBOS_URL", "http://cerbos:3592").rstrip("/")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
MINIO_REGION = os.getenv("MINIO_REGION", "us-east-1")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

s3 = boto3.client(
    "s3",
    endpoint_url=MINIO_ENDPOINT,
    aws_access_key_id=os.environ["MINIO_ACCESS_KEY"],
    aws_secret_access_key=os.environ["MINIO_SECRET_KEY"],
    region_name=MINIO_REGION,
    use_ssl=MINIO_SECURE,
)

app = FastAPI(title="MinIO Cerbos Authorization Gateway", version="1.0.0")


@app.on_event("startup")
async def startup():
    app.state.cerbos = httpx.AsyncClient(base_url=CERBOS_URL, timeout=5.0)


@app.on_event("shutdown")
async def shutdown():
    await app.state.cerbos.aclose()


def principal_from_request(request: Request) -> dict:
    """Identity headers must be overwritten by a trusted authentication proxy."""
    user_id = request.headers.get("X-Auth-User")
    roles_header = request.headers.get("X-Auth-Roles", "")
    org = request.headers.get("X-Auth-Org", "")
    path_prefix = request.headers.get("X-Auth-Path-Prefix", "")

    if not user_id:
        return {
            "id": "anonymous",
            "roles": ["anonymous"],
            "attr": {"org": "public"},
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


async def authorize(principal: dict, bucket: str, key: str, action: str) -> bool:
    payload = {
        "principal": principal,
        "resources": [{
            "resource": {
                "kind": "minio_object",
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
        log.exception("MinIO request failed")
        raise HTTPException(status_code=502, detail="Storage backend error")
