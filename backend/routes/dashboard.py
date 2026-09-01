from fastapi import APIRouter
from ..models.schemas import DashboardResponse, RecentScan, ThreatStatistics
from ..data.sample_threats import RECENT_SCANS, THREAT_STATS

router = APIRouter()

@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard():
    """
    Get dashboard summary with recent activity and statistics
    """
    recent_scans = [
        RecentScan(**scan) for scan in RECENT_SCANS
    ]
    
    threat_stats = ThreatStatistics(**THREAT_STATS)
    
    return DashboardResponse(
        overall_trust_score=72,
        threats_detected=len(RECENT_SCANS),
        websites_scanned=12,
        transactions_analyzed=5,
        recent_scans=recent_scans,
        threat_statistics=threat_stats
    )
