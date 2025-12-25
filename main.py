from __future__ import annotations

import os
import uvicorn
from passwordforge.api import create_app

app = create_app()

if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5005"))
    uvicorn.run("main:app", host=host, port=port, reload=False)
