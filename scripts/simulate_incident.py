#!/usr/bin/env python3
"""
Incident Simulator — Test the agent with realistic fake incidents.
Usage: python scripts/simulate_incident.py [cicd|k8s|server|dockerfile]
"""
import asyncio
import hashlib
import hmac
import json
import os
import sys
import httpx
from dotenv import load_dotenv

BASE_URL = "http://localhost:8000"

INCIDENTS = {
    "cicd": {
        "type": "cicd",
        "source": "manual",
        "repo": "my-org/my-app",
        "run_id": 12345678,
        "workflow_name": "Deploy to Production",
        "branch": "main",
        "commit": "abc1234",
        "description": "Pipeline failed at 'npm ci' step with EINTEGRITY checksum error. The package-lock.json may be out of sync.",
        "raw_logs": """
Run npm ci
npm WARN saveError ENOENT: no such file or directory, open 'package-lock.json'
npm ERR! code EINTEGRITY
npm ERR! sha512-XXXXXX integrity checksum failed when using sha512: wanted sha512-XXXXXX but got sha512-YYYYYY
npm ERR! Found: lodash@4.17.20
npm ERR! node_modules/lodash
npm ERR! A complete log of this run can be found in: /root/.npm/_logs/2024-01-15T10_23_45_678Z-debug.log
Error: Process completed with exit code 1.
""",
    },

    "k8s": {
        "type": "k8s",
        "source": "manual",
        "namespace": "production",
        "pod": "api-deployment",
        "alertname": "PodCrashLooping",
        "description": "API pods are CrashLoopBackOff. Multiple OOMKilled events in the last 10 minutes.",
        "raw_context": {
            "pods": [{
                "name": "api-deployment-7d9f8b-xk2p9",
                "phase": "Running",
                "container_states": [{
                    "name": "api",
                    "ready": False,
                    "restart_count": 12,
                    "state": "waiting",
                    "reason": "CrashLoopBackOff",
                }],
                "resources": {
                    "api": {
                        "requests": {"memory": "64Mi", "cpu": "50m"},
                        "limits": {"memory": "128Mi", "cpu": "100m"},
                    }
                },
                "logs": {
                    "api_previous": """
FATAL: heap out of memory
JavaScript heap out of memory
<--- Last few GCs --->
[1] 45678 ms: Mark-sweep 120.5 (128.5) -> 120.1 (128.5) MB, 1203.3 ms
FATAL ERROR: CALL_AND_RETRY_LAST Allocation failed - JavaScript heap out of memory
 1: 0xb7c5e0 node::Abort() [node]
Killed
""",
                },
            }],
            "events": [
                {"reason": "OOMKilling", "message": "Memory limit reached, container api killed", "object": "Pod/api-deployment-7d9f8b-xk2p9", "count": 8},
                {"reason": "BackOff", "message": "Back-off restarting failed container", "object": "Pod/api-deployment-7d9f8b-xk2p9", "count": 12},
            ],
        },
    },

    "server": {
        "type": "server",
        "source": "manual",
        "alertname": "NginxDown",
        "description": "Nginx service is down. Port 80 and 443 not responding.",
        "raw_logs": """
Jan 15 10:23:45 web-01 nginx[12345]: nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)
Jan 15 10:23:45 web-01 nginx[12345]: nginx: [emerg] bind() to 0.0.0.0:443 failed (98: Address already in use)
Jan 15 10:23:45 web-01 systemd[1]: nginx.service: Control process exited, code=exited, status=1/FAILURE
Jan 15 10:23:45 web-01 systemd[1]: Failed to start A high performance web server and a reverse proxy server.
""",
    },

    "dockerfile": {
        "type": "dockerfile",
        "source": "manual",
        "description": "Docker build failing, image is 2.1GB, security scan showing critical vulnerabilities.",
        "raw_dockerfile": """FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
RUN npm run build
EXPOSE 3000
CMD node server.js
""",
        "build_error": """
Step 4/6 : RUN npm install
 ---> Running in a9b3c4d5e6f7
npm WARN deprecated uuid@3.4.0: Please upgrade to version 7 or higher
npm WARN deprecated request@2.88.2: request has been deprecated
added 1847 packages in 2m 34s
 ---> a1b2c3d4e5f6
Step 5/6 : RUN npm run build
 ---> Running in b2c3d4e5f6a7
> myapp@1.0.0 build
> webpack --mode production
ERROR in ./src/index.js
Module not found: Error: Can't resolve './missing-module'
""",
    },
}


async def simulate(incident_type: str):
    load_dotenv()
    incident = INCIDENTS.get(incident_type)
    if not incident:
        print(f"Unknown type: {incident_type}. Choose from: {list(INCIDENTS.keys())}")
        sys.exit(1)

    print(f"\n🚨 Simulating {incident_type.upper()} incident...")
    print(f"Sending to {BASE_URL}/webhook/manual\n")

    body = json.dumps(incident).encode()
    headers = {"Content-Type": "application/json"}
    secret = os.getenv("WEBHOOK_SECRET", "")
    if secret:
        headers["X-Hub-Signature-256"] = (
            "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        )
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{BASE_URL}/webhook/manual", content=body, headers=headers)
        print(f"Status: {resp.status_code}")
        print(f"Response: {json.dumps(resp.json(), indent=2)}")
        resp.raise_for_status()

    print(f"\n✅ Incident submitted! Check {BASE_URL}/audit for results.")
    print(f"Agent is processing in the background — check your Slack channel.")


if __name__ == "__main__":
    incident_type = sys.argv[1] if len(sys.argv) > 1 else "k8s"
    asyncio.run(simulate(incident_type))
