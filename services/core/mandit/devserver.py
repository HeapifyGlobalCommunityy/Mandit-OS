"""Local test server for the parts of Mandit OS that exist: site scan, domain info, merchants.

    cd services/core && python -m mandit.devserver        # http://127.0.0.1:8000/docs

There is no authentication yet, so it binds to the loopback address only.
"""

from __future__ import annotations

import uvicorn
from dotenv import find_dotenv, load_dotenv
from fastapi import FastAPI

from mandit.grounding import api as grounding_api
from mandit.safety import api as safety_api

app = FastAPI(title="Mandit OS (local test server)")
app.include_router(safety_api.router)
app.include_router(safety_api.content_router)
app.include_router(grounding_api.router)

if __name__ == "__main__":
    load_dotenv(find_dotenv(usecwd=True))
    uvicorn.run(app, host="127.0.0.1", port=8000)
