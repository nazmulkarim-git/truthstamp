from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional, Literal

ProvenanceState = Literal[
    "VERIFIED_ORIGINAL",
    "ALTERED_OR_BROKEN_PROVENANCE",
    "UNVERIFIABLE_NO_PROVENANCE",
]


class ToolStatus(BaseModel):
    name: str
    available: bool
    version: Optional[str] = None
    notes: Optional[str] = None


class Finding(BaseModel):
    key: str
    value: Any = None
    confidence: Literal["PROVABLE", "INFERRED", "UNKNOWN"] = "UNKNOWN"
    notes: Optional[str] = None


class AnalysisResult(BaseModel):
    # Core file info
    filename: str
    media_type: str
    sha256: str
    bytes: int = 0

    # Optional context
    role: Optional[str] = None
    use_case: Optional[str] = None

    # Workspace links (optional)
    case_id: Optional[str] = None
    evidence_id: Optional[str] = None

    # High-level interpretation
    provenance_state: ProvenanceState
    summary: str = ""

    # Structured data
    tools: List[ToolStatus] = Field(default_factory=list)
    c2pa: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ffprobe: Dict[str, Any] = Field(default_factory=dict)

    ai_disclosure: Dict[str, Any] = Field(default_factory=dict)
    transformations: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)

    derived_timeline: Dict[str, Any] = Field(default_factory=dict)
    metadata_consistency: Dict[str, Any] = Field(default_factory=dict)
    metadata_completeness: Dict[str, Any] = Field(default_factory=dict)

    decision_context: Dict[str, Any] = Field(default_factory=dict)
    what_would_make_verifiable: List[str] = Field(default_factory=list)
    what_this_report_is: List[str] = Field(default_factory=list)
    what_this_report_is_not: List[str] = Field(default_factory=list)
    report_integrity: Dict[str, Any] = Field(default_factory=dict)

    # Optional narrative extras
    limitations: List[str] = Field(default_factory=list)


class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None


class CaseItem(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    created_at: str


class EvidenceItem(BaseModel):
    id: str
    case_id: str
    filename: Optional[str] = None
    sha256: Optional[str] = None
    media_type: Optional[str] = None
    bytes: Optional[int] = None
    provenance_state: Optional[str] = None
    summary: Optional[str] = None
    created_at: str


class EventItem(BaseModel):
    id: str
    case_id: str
    evidence_id: Optional[str] = None
    event_type: str
    actor: Optional[str] = None
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
