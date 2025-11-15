from pydantic import BaseModel, Field


class AccessDetails(BaseModel):
    """
    Represents access details with IP address and accessed resource.
    """
    ip_address: str = Field(..., description="IP address of the access")
    accessed_resource: str = Field(..., description="URL of the accessed resource")

