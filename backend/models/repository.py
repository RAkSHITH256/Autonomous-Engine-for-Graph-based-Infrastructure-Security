from pydantic import BaseModel, Field


class Repository(BaseModel):
    """
    Source-code repository represented in the AEGIS security graph.
    """

    repository_id: str = Field(
        ...,
        description="Unique identifier for the source repository",
    )

    name: str = Field(
        ...,
        description="Repository name",
    )

    url: str | None = Field(
        default=None,
        description="Repository URL",
    )

    branch: str = Field(
        default="main",
        description="Source branch associated with the build",
    )

    commit_sha: str | None = Field(
        default=None,
        description="Commit SHA associated with the build",
    )

    provider: str = Field(
        default="github",
        description="Source-control provider",
    )
