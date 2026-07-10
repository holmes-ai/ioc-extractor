"""ioc-extractor: extract, validate, and normalize Indicators of Compromise."""

from ioc_extractor.core.extractor import extract
from ioc_extractor.core.models import IOC, ExtractionResult, IOCType

__version__ = "0.1.1"
__all__ = ["IOC", "ExtractionResult", "IOCType", "extract"]
