from typing import Any


class SBOMParser:
    """
    Parses CycloneDX JSON SBOM documents into a normalized
    dependency representation used by AEGIS.
    """

    def parse(
        self,
        sbom: dict[str, Any],
    ) -> list[dict[str, Any]]:

        if not isinstance(sbom, dict):
            raise TypeError(
                "SBOM must be a dictionary."
            )

        components = sbom.get(
            "components",
            [],
        )

        if not isinstance(components, list):
            raise ValueError(
                "SBOM 'components' must be a list."
            )

        dependencies = []

        for component in components:

            if not isinstance(component, dict):
                continue

            name = component.get("name")

            if not name:
                continue

            dependency = {
                "name": name,

                "version": component.get(
                    "version",
                    "UNKNOWN",
                ),

                "type": component.get(
                    "type",
                    "library",
                ),

                "purl": component.get(
                    "purl",
                ),

                "group": component.get(
                    "group",
                ),

                "scope": component.get(
                    "scope",
                    "required",
                ),
            }

            dependencies.append(
                dependency
            )

        return dependencies