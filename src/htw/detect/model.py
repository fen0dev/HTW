"""Result model for stack detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LANGUAGE = "language"
PACKAGE_MANAGER = "package_manager"
CONTAINER = "container"
IAC = "iac"
CLOUD = "cloud"
CI_CD = "ci_cd"
DEPENDENCY_AUTOMATION = "dependency_automation"
VCS = "vcs"

CATEGORIES = (
    LANGUAGE,
    PACKAGE_MANAGER,
    CONTAINER,
    IAC,
    CLOUD,
    CI_CD,
    DEPENDENCY_AUTOMATION,
    VCS,
)
CATEGORY_TITLES = {
    LANGUAGE: "Languages",
    PACKAGE_MANAGER: "Package managers",
    CONTAINER: "Containers",
    IAC: "Infrastructure as code",
    CLOUD: "Cloud and platforms",
    CI_CD: "CI/CD pipelines",
    DEPENDENCY_AUTOMATION: "Dependency automation",
    VCS: "Version control",
}

MAX_EVIDENCE = 5


@dataclass
class Component:
    """One detected part of the stack, with the files that prove it."""

    category: str
    name: str
    count: int = 0
    evidence: list[str] = field(default_factory=list)
    confidence: str = "high"
    attributes: dict[str, Any] = field(default_factory=dict)

    def add(self, path: str, confidence: str = "high") -> None:
        self.count += 1
        if len(self.evidence) < MAX_EVIDENCE and path not in self.evidence:
            self.evidence.append(path)
        order = ("low", "medium", "high")
        if self.count == 1 or order.index(confidence) > order.index(self.confidence):
            self.confidence = confidence

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "category": self.category,
            "name": self.name,
            "count": self.count,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }
        if self.attributes:
            data["attributes"] = {
                key: sorted(value) if isinstance(value, set) else value
                for key, value in sorted(self.attributes.items())
            }
        return data


@dataclass
class StackProfile:
    """Everything detected under one asset root."""

    components: dict[tuple[str, str], Component] = field(default_factory=dict)
    files_seen: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)

    def record(self, category: str, name: str, path: str, confidence: str = "high") -> Component:
        component = self.components.get((category, name))
        if component is None:
            component = Component(category, name)
            self.components[(category, name)] = component
        component.add(path, confidence)
        return component

    def of(self, category: str) -> list[Component]:
        found = [c for c in self.components.values() if c.category == category]
        return sorted(found, key=lambda c: (-c.count, c.name))

    def names(self, category: str) -> set[str]:
        return {c.name for c in self.components.values() if c.category == category}

    def has(self, category: str, name: str | None = None) -> bool:
        if name is None:
            return any(c.category == category for c in self.components.values())
        return (category, name) in self.components

    @property
    def languages(self) -> set[str]:
        return self.names(LANGUAGE)

    @property
    def ecosystems(self) -> set[str]:
        result: set[str] = set()
        for component in self.of(PACKAGE_MANAGER):
            ecosystem = component.attributes.get("ecosystem")
            if isinstance(ecosystem, str):
                result.add(ecosystem)
        return result

    @property
    def is_git_repository(self) -> bool:
        return self.has(VCS, "Git")

    def to_dict(self) -> dict[str, object]:
        return {
            "files_seen": self.files_seen,
            "truncated": self.truncated,
            "notes": list(self.notes),
            "components": {
                category: [c.to_dict() for c in self.of(category)]
                for category in CATEGORIES
                if self.has(category)
            },
        }
