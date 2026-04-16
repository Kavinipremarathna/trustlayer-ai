from typing import Literal

from pydantic import BaseModel, Field


ScanScope = Literal["quick", "balanced", "strict"]


class URLScanRequest(BaseModel):
    url: str = Field(min_length=1)
    scope: ScanScope = "balanced"


class RiskSignal(BaseModel):
    rule: str
    message: str
    points: int
    recommendation: str


class RiskResponse(BaseModel):
    score: int
    label: str
    reasons: list[str]
    signals: list[RiskSignal]
    scope: ScanScope
    confidence: str
    recommendations: list[str]


class ScanResponse(BaseModel):
    analysis: dict
    risk: RiskResponse