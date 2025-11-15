import random
from typing import Union

from model import AccessDetails, ThreatLevel, MLServiceError


class ThreatAssessmentService:
    """
    Service for assessing the threat level of login/access attempts based on IP address and accessed resource.
    
    This service evaluates security risks by analyzing access patterns and categorizing them into 
    four threat levels: CRITICAL, HIGH, MEDIUM, and LOW.
    
    Threat Assessment Logic:
        - CRITICAL: IP address matches known critical IP prefixes (highest priority)
        - HIGH: Accessed resource is a high-risk endpoint (admin, reports, settings)
        - LOW: Accessed resource is a low-risk endpoint (dashboard, profile)
        - MEDIUM: All other access attempts (default)
    """

    def __init__(self):
        self.critical_ips_prefixes = ["141.", "68."]
        self.high_risk_resources = ["/admin", "/reports", "/settings"]
        self.low_rist_resources = ["/dashboard", "/profile"]

    async def assess_threat_level(self, ad: AccessDetails) -> Union[ThreatLevel, ]:
        """
        Assess the threat level of an access attempt.
        Args:
            ad (AccessDetails): The access details containing IP address and accessed resource.
        
        Returns:
            ThreatLevel: The assessed threat level (CRITICAL, HIGH, MEDIUM, or LOW).

        Raises:
            MLServiceError: If an error occurs during threat assessment.
        """
        if random.randint(1, 100) <= 5:
            raise MLServiceError()
        if any(ad.ip_address.startswith(p) for p in self.critical_ips_prefixes):
            return ThreatLevel.CRITICAL
        elif any(ad.accessed_resource.endswith(res) for res in self.high_risk_resources):
            return ThreatLevel.HIGH
        elif any(ad.accessed_resource.endswith(res) for res in self.low_rist_resources):
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MEDIUM
