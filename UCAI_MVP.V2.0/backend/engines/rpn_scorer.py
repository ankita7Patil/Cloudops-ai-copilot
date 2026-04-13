from dataclasses import dataclass

@dataclass
class RPNInput:
    likelihood: float          # 1-5: how likely is this to be exploited/fail
    impact: float              # 1-5: business impact if it does
    detectability: float       # 1-5: how easily detected (HIGHER = more detectable = LOWER risk)
    internet_exposed: bool
    pii_adjacent: bool
    business_critical: bool
    ai_workload: bool = False
    change_freeze: bool = False
    active_incident: bool = False

class RPNScorer:
    TIERS = {
        "TIER_1_AUTO": (0, 15),      # Low risk: auto-execute
        "TIER_2_SUGGEST": (15, 35),  # Medium: suggest with 1-click approval
        "TIER_3_IAC": (35, 9999),    # High: IaC patch only, full review
    }
    
    def score(self, inp: RPNInput) -> dict:
        base = inp.likelihood * inp.impact * (1.0 / max(inp.detectability, 0.1))
        multiplier = 1.0
        if inp.internet_exposed:    multiplier *= 3.0
        if inp.pii_adjacent:        multiplier *= 2.0
        if inp.business_critical:   multiplier *= 2.0
        if inp.ai_workload:         multiplier *= 1.5
        
        rpn = round(base * multiplier, 2)
        tier = self._classify_tier(rpn, inp)
        
        return {
            "rpn_score": rpn,
            "base_score": round(base, 2),
            "multiplier": round(multiplier, 2),
            "tier": tier,
            "should_block": inp.change_freeze or inp.active_incident,
            "block_reason": "Change freeze active" if inp.change_freeze else ("Active P1 incident" if inp.active_incident else None)
        }
    
    def _classify_tier(self, rpn: float, inp: RPNInput) -> str:
        if inp.change_freeze or inp.active_incident:
            return "TIER_3_IAC"  # Always escalate during risky periods
        for tier, (low, high) in self.TIERS.items():
            if low <= rpn < high:
                return tier
        return "TIER_3_IAC"
