# Elastic Cloud to NFS CSV exporter

This on-prem service accepts one complete Discover Inspector request, paginates Elastic Cloud with a point in time and `search_after`, and writes a ZIP containing one CSV plus a JSON manifest to an NFS-mounted directory. Tines receives only the accepted job and final metadata.

## Run

1. Mount the customer NFS export share at `/mnt/security-exports`.
2. Copy `.env.example` to `.env` and provide the Elastic API key, API token and Tines callback URL.
3. Start the service:

   ```sh
   docker compose up -d --build
   ```

4. Submit an export through the local service or through Tines Tunnel:

   ```http
   POST /exports
   Authorization: Bearer <EXPORT_API_TOKEN>
   Content-Type: application/json

   {
     "export_name": "security-alerts-2026-08-01-to-2026-08-18",
     "request": "POST /logs-*/_async_search?...\n{...}"
   }
   ```

The service returns HTTP 202 with a job ID. `GET /jobs/<job-id>` returns lightweight status. Completed files are atomically renamed to the generated artifact name ending in `.zip`. By default, each archive contains sequential CSV parts with approximately 200,000 data rows each; a part may exceed the target by at most one Elasticsearch page because checkpoints and part rotation happen only at safe page boundaries. Set `CSV_ROWS_PER_FILE` to change that limit. Staged parts remain hidden while a job is incomplete and are removed after successful ZIP assembly.

The same exporter process sends the completion callback to Tines. Failed
callbacks are retried from the completed manifest every
`CALLBACK_RETRY_SECONDS` until Tines accepts them. A delivery marker prevents
duplicate completion emails after container restarts; no callback sidecar is
required.

`export_name` is optional. When supplied, it is sanitized and combined with the job's random suffix to produce a readable, collision-safe ZIP name. Every CSV part begins with a UTF-8 byte-order mark for reliable Unicode handling in Windows Excel.

## Restart recovery

Every completed Elasticsearch page is flushed to a staged CSV part and recorded in an atomic checkpoint with its `search_after` value and PIT ID. When the container restarts, queued or running jobs are restored automatically, uncommitted bytes are truncated, and collection resumes from the last committed page. The default PIT keep-alive is one hour. Restart within that window to retain exact snapshot consistency; if the PIT has expired, the export fails rather than silently continuing from a different snapshot.

## NFS and download service

Mount NFS on the Docker host and bind-mount it into the container. Set
`NFS_DISPLAY_PATH` to the path analysts use to open the same share, for example
`\\\\fileserver\\security-exports` for a Windows SMB share or
`/mnt/security-exports` for Linux NFS clients. The completion callback includes
the full customer-facing path as `nfs_path`, so Tines can place it in the email.

Keep storage access internal. For NFSv4, allow TCP 2049 only between the exporter
host and the NFS server. If Windows analysts access the same NAS through SMB,
allow TCP 445 only from the analyst network to the NAS. Do not expose TCP 2049
or TCP 445 through ngrok or directly to the internet.

`DOWNLOAD_BASE_URL` is optional and is only for a separately managed internal
HTTPS download service; it is not required when analysts retrieve files from the
NFS/SMB share.
