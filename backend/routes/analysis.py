from fastapi import APIRouter, File, UploadFile, HTTPException
from ..models.schemas import (
    URLAnalysisRequest, URLAnalysisResponse,
    IdentityVerificationRequest, IdentityVerificationResponse,
    DocumentAnalysisResponse,
    TransactionAnalysisRequest, TransactionAnalysisResponse,
    MessageAnalysisRequest, MessageAnalysisResponse,
    ScamNetworkResponse, ScamEntity, ScamRelationship
)
from ..services.url_analyzer import URLAnalyzer
from ..services.identity_analyzer import IdentityAnalyzer
from ..services.document_analyzer import DocumentAnalyzer, TransactionAnalyzer
from ..services.message_analyzer import MessageAnalyzer
from ..data.sample_threats import SAMPLE_SCAM_NETWORK

router = APIRouter()

@router.post("/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """
    Analyze a URL for trust and security indicators
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Validate URL format
    if not request.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")
    
    result = URLAnalyzer.analyze(request.url, request.awareness_level)
    return result

@router.post("/analyze/identity", response_model=IdentityVerificationResponse)
async def analyze_identity(request: IdentityVerificationRequest):
    """
    Verify digital identity consistency
    """
    if not request.name:
        raise HTTPException(status_code=400, detail="Name is required")
    
    result = IdentityAnalyzer.analyze(
        name=request.name,
        email=request.email,
        phone=request.phone,
        website=request.website,
        organization_id=request.organization_id
    )
    return result

@router.post("/analyze/document", response_model=DocumentAnalysisResponse)
async def analyze_document(file: UploadFile = File(...)):
    """
    Analyze document for authenticity and manipulation
    """
    try:
        content = await file.read()
        content_str = content.decode('utf-8', errors='ignore')
        
        result = DocumentAnalyzer.analyze(content_str, file.filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing document: {str(e)}")

@router.post("/analyze/transaction", response_model=TransactionAnalysisResponse)
async def analyze_transaction(request: TransactionAnalysisRequest):
    """
    Analyze complete transaction chain for consistency
    """
    if not request.message or not request.organization:
        raise HTTPException(status_code=400, detail="Message and organization are required")
    
    result = TransactionAnalyzer.analyze(
        message=request.message,
        website_url=request.website_url,
        upi_id=request.upi_id,
        organization=request.organization
    )
    return result

@router.post("/analyze/message", response_model=MessageAnalysisResponse)
async def analyze_message(request: MessageAnalysisRequest):
    """
    Analyze message for phishing/scam indicators
    """
    if not request.message:
        raise HTTPException(status_code=400, detail="Message is required")
    
    result = MessageAnalyzer.analyze(request.message, request.awareness_level)
    return result

@router.get("/scam-network", response_model=ScamNetworkResponse)
async def get_scam_network():
    """
    Get scam relationship network visualization data
    """
    entities = [
        ScamEntity(**entity) for entity in SAMPLE_SCAM_NETWORK["entities"]
    ]
    relationships = [
        ScamRelationship(**rel) for rel in SAMPLE_SCAM_NETWORK["relationships"]
    ]
    
    return ScamNetworkResponse(
        entities=entities,
        relationships=relationships,
        scam_patterns=SAMPLE_SCAM_NETWORK["patterns"]
    )
