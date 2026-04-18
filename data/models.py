from enum import Enum
from uuid import uuid4
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, field_validator


class AttackType(str, Enum):
    # Seed library values
    domain_probe = "domain_probe"
    jailbreak = "jailbreak"
    prompt_injection = "prompt_injection"
    encoding_obfuscation = "encoding_obfuscation"
    multilingual_bypass = "multilingual_bypass"
    # Legacy / additional taxonomy
    roleplay_jailbreak = "roleplay_jailbreak"
    multi_turn_escalation = "multi_turn_escalation"
    sensitive_info_disclosure = "sensitive_info_disclosure"
    excessive_agency = "excessive_agency"
    unknown = "unknown"


class AttackTechnique(str, Enum):
    # Seed library values
    alternate_reality_roleplay = "alternate_reality_roleplay"
    base64 = "base64"
    character_capture = "character_capture"
    context_recall = "context_recall"
    dan_roleplay = "dan_roleplay"
    direct_injection = "direct_injection"
    direct_request = "direct_request"
    format_shift = "format_shift"
    hypothetical_framing = "hypothetical_framing"
    indirect_injection = "indirect_injection"
    jurisdiction_claim = "jurisdiction_claim"
    language_probe = "language_probe"
    language_switch = "language_switch"
    leetspeak = "leetspeak"
    persona_roleplay = "persona_roleplay"
    rag_extraction = "rag_extraction"
    refusal_bypass = "refusal_bypass"
    system_prompt_extraction = "system_prompt_extraction"
    token_smuggling = "token_smuggling"
    unicode_homoglyph = "unicode_homoglyph"
    validation_framing = "validation_framing"
    # Legacy / additional taxonomy
    dan = "dan"
    rot13 = "rot13"
    homoglyph = "homoglyph"
    incremental_escalation = "incremental_escalation"
    unknown = "unknown"


class AttackConfig(BaseModel):
    attack_type: AttackType
    attack_technique: AttackTechnique
    prompt_text: str
    target_model: str
    system_prompt: Optional[str] = None
    tags: list[str] = []

    @field_validator("prompt_text", mode="after")
    @classmethod
    def prompt_must_be_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("prompt_text must not be empty")
        return v


class AttackResult(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    attack_id: str = None  # type: ignore[assignment]
    attack_type: AttackType
    attack_technique: AttackTechnique
    prompt_text: str
    target_model: str
    response_text: Optional[str] = None
    timestamp: datetime = None  # type: ignore[assignment]
    success: Optional[bool] = None
    severity_score: Optional[float] = None
    judge_reasoning: Optional[str] = None
    error: Optional[str] = None
    # Domain metadata (from YAML seed, persisted for analytics)
    financial_subdomain: Optional[str] = None   # e.g. "3a", "3b", "3c", or None for generic attacks
    tags: list[str] = []                         # free-form labels from the seed file

    def model_post_init(self, __context) -> None:
        if self.attack_id is None:
            object.__setattr__(self, "attack_id", str(uuid4()))
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.utcnow())

    @field_validator("prompt_text", mode="after")
    @classmethod
    def prompt_must_be_nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("prompt_text must not be empty")
        return v

    @field_validator("severity_score", mode="after")
    @classmethod
    def severity_in_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("severity_score must be between 0.0 and 10.0")
        return v


def result_from_config(config: AttackConfig) -> AttackResult:
    """Create a fresh AttackResult from an AttackConfig, ready for execution."""
    return AttackResult(
        attack_type=config.attack_type,
        attack_technique=config.attack_technique,
        prompt_text=config.prompt_text,
        target_model=config.target_model,
    )
