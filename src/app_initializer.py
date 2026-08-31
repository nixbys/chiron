# src/app_initializer.py
"""Initialize all application components and dependencies."""
import json
import os
import logging
from typing import Dict, Any

from src.constants import (
    DATA_DIR, PERSONAL_DIR, RUNBOOK_DIR, UPLOAD_DIR,
    SESSIONS_FILE, DEFAULT_HOST, OPENAI_API_KEY
)
from src.memory import MemoryManager
from src.memory_provider import MemoryProviderRegistry, NativeMemoryProvider
from services.memory.skills import SkillsManager
from core.session_manager import SessionManager
from core.models import set_session_manager
from src.personal_docs import PersonalDocsManager
from src.preset_manager import PresetManager
from src.chat_processor import ChatProcessor
from src.model_discovery import ModelDiscovery
from src.chat_handler import ChatHandler
from src.research_handler import ResearchHandler
from src.upload_handler import UploadHandler
from src.tool_utils import set_upload_handler
from src.search import update_search_config

logger = logging.getLogger(__name__)


def _load_and_migrate_provider_api_keys(data_dir: str) -> Dict[str, str]:
    """Load data/api_keys.json (provider name -> API key, e.g. "brave"),
    decrypted via secret_storage -- and, one time, migrate any value still
    encrypted under the retired src/api_key_manager.py's separate Fernet
    key (data/.key) onto secret_storage's key/`enc:` convention, rewriting
    the file so the legacy-key fallback is never needed again. Tolerates a
    missing/corrupt/wrong-shaped file the same way the retired
    APIKeyManager.load() did -- treated as "no stored keys," never a
    startup crash."""
    path = os.path.join(data_dir, "api_keys.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Failed to read API keys file: %s", e)
        return {}
    if not isinstance(raw, dict):
        logger.warning("API keys file has unexpected shape (%s); ignoring", type(raw).__name__)
        return {}

    from src.secret_storage import decrypt, encrypt, is_encrypted, load_legacy_api_key_manager_fernet

    decrypted: Dict[str, str] = {}
    rewritten: Dict[str, str] = {}
    migrated = False
    legacy_fernet = None
    for provider, value in raw.items():
        if not isinstance(value, str) or not value:
            continue
        provider = str(provider)
        if is_encrypted(value):
            decrypted[provider] = decrypt(value)
            rewritten[provider] = value
            continue
        # Not in the new enc: form -- try the retired api_key_manager key
        # before assuming it's genuinely legacy plaintext.
        if legacy_fernet is None:
            legacy_fernet = load_legacy_api_key_manager_fernet() or False
        plaintext = value
        if legacy_fernet:
            try:
                plaintext = legacy_fernet.decrypt(value.encode()).decode()
            except Exception:
                plaintext = value
        decrypted[provider] = plaintext
        rewritten[provider] = encrypt(plaintext)
        migrated = True

    if migrated:
        try:
            tmp_path = path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(rewritten, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            logger.info("Migrated provider API key(s) in api_keys.json to secret_storage encryption")
        except OSError as e:
            logger.warning("Failed to persist migrated api_keys.json: %s", e)

    return decrypted


def create_directories():
    """Create necessary directories if they don't exist."""
    for directory in (DATA_DIR, PERSONAL_DIR, RUNBOOK_DIR, UPLOAD_DIR):
        os.makedirs(directory, exist_ok=True)
        
def initialize_managers(base_dir: str, rag_manager=None) -> Dict[str, Any]:
    """
    Initialize all manager and handler instances.

    Args:
        base_dir: Base directory path
        rag_manager: RAG manager instance (optional)
    Returns:
        Dictionary containing all initialized components
    """
    # Create directories first
    create_directories()

    # Initialize core managers
    memory_manager = MemoryManager(DATA_DIR)
    skills_manager = SkillsManager(DATA_DIR)
    session_manager = SessionManager(SESSIONS_FILE)
    set_session_manager(session_manager)  # Enable Session.add_message() persistence
    upload_handler = UploadHandler(base_dir, UPLOAD_DIR)
    session_manager.upload_handler = upload_handler
    set_upload_handler(upload_handler)
    personal_docs_manager = PersonalDocsManager(PERSONAL_DIR, rag_manager)
    preset_manager = PresetManager(DATA_DIR)

    # Initialize memory vector store (share embedding model with RAG if available)
    memory_vector = None
    try:
        from src.memory_vector import MemoryVectorStore
        embedding_model = getattr(rag_manager, '_model', None) if rag_manager else None
        memory_vector = MemoryVectorStore(DATA_DIR, embedding_model=embedding_model)
        if memory_vector.healthy:
            # Rebuild index from existing memories if empty
            if memory_vector.count() == 0:
                existing = memory_manager.load()
                if existing:
                    memory_vector.rebuild(existing)
                    logger.info(f"Rebuilt memory vector index from {len(existing)} existing entries")
            logger.info("MemoryVectorStore initialized")
        else:
            # Keep the unhealthy object (do NOT reset to None): consumers gate on
            # `.healthy`, and service_health.chromadb_health() needs a present
            # object to report DEGRADED/DOWN instead of DISABLED ("not configured").
            logger.warning("MemoryVectorStore DEGRADED: ChromaDB vector memory unavailable")
    except Exception as e:
        logger.warning(f"MemoryVectorStore DEGRADED: {e}")
        memory_vector = None

    memory_provider_registry = MemoryProviderRegistry([
        NativeMemoryProvider(memory_manager, memory_vector),
    ])

    # Initialize processors
    chat_processor = ChatProcessor(memory_manager, personal_docs_manager, memory_vector=memory_vector, skills_manager=skills_manager)
    research_handler = ResearchHandler()
    
    # Initialize chat handler with all dependencies
    chat_handler = ChatHandler(
        session_manager=session_manager,
        memory_manager=memory_manager,
        chat_processor=chat_processor,
        research_handler=research_handler,
        preset_manager=preset_manager,
        upload_handler=upload_handler,
    )
    
    # Initialize model discovery
    model_discovery = ModelDiscovery(DEFAULT_HOST, OPENAI_API_KEY)
    
    # Load and apply saved API keys
    saved_keys = _load_and_migrate_provider_api_keys(DATA_DIR)
    if "brave" in saved_keys:
        update_search_config(api_key=saved_keys["brave"])
        logger.info("Loaded Brave API key from saved configuration")

    return {
        "memory_manager": memory_manager,
        "memory_vector": memory_vector,
        "memory_provider_registry": memory_provider_registry,
        "skills_manager": skills_manager,
        "session_manager": session_manager,
        "upload_handler": upload_handler,
        "personal_docs_manager": personal_docs_manager,
        "preset_manager": preset_manager,
        "chat_processor": chat_processor,
        "research_handler": research_handler,
        "chat_handler": chat_handler,
        "model_discovery": model_discovery,
        "current_presets": preset_manager.presets,
        "PERSONAL_INDEX": personal_docs_manager.index
    }
