from pydantic import BaseModel, Field
from typing import Optional
from model.threat_level import ThreatLevel


class Report(BaseModel):
    """
    Represents a threat assessment report with aggregated incident data.
    """
    threat_level: ThreatLevel = Field(..., description="Threat level classification")
    incidents_count: int = Field(..., ge=0, description="Number of incidents for this threat level")
    first_incident: Optional[int] = Field(None, description="Timestamp of the first incident")
    last_incident: Optional[int] = Field(None, description="Timestamp of the last incident")


