from pydantic import BaseModel, Field


class BuildProvenance(BaseModel):
    """
    Evidence describing how a container image was produced by CI/CD.
    """

    provider: str = Field(
        default="github-actions",
        description="CI/CD provider that produced the build",
    )

    repository: str = Field(
        ...,
        description="Source repository that produced the image",
    )

    workflow: str = Field(
        ...,
        description="CI/CD workflow name",
    )

    run_id: str = Field(
        ...,
        description="Unique CI/CD workflow run ID",
    )

    run_number: int | None = Field(
        default=None,
        description="Human-readable CI/CD run number",
    )

    commit_sha: str = Field(
        ...,
        description="Source commit used to build the image",
    )

    branch: str = Field(
        ...,
        description="Source branch used for the build",
    )

    image: str = Field(
        ...,
        description="Container image reference",
    )

    image_id: str = Field(
        ...,
        description="Immutable Docker image ID",
    )

    created: str | None = Field(
        default=None,
        description="Image creation timestamp",
    )
