from fastapi import FastAPI

app = FastAPI(
    title="AEGIS",
    description="Autonomous Engine for Graph-based Infrastructure Security",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AEGIS",
        "version": "0.1.0",
    }