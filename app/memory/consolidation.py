"""
Intelligent Memory Consolidation System for SNODE
==================================================

Uses LLM analysis to automatically consolidate related memories,
reducing duplication and improving retrieval accuracy.

Based on agent-zero's consolidation system, adapted for SNODE.
"""
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

from .vector import VectorMemory, get_vector
from .areas import MemoryArea, classify_memory_area


class ConsolidationAction(Enum):
    """Actions that can be taken during memory consolidation."""
    MERGE = "merge"
    REPLACE = "replace"
    KEEP_SEPARATE = "keep_separate"
    UPDATE = "update"
    SKIP = "skip"


@dataclass
class ConsolidationConfig:
    """Configuration for memory consolidation behavior."""
    similarity_threshold: float = 0.7  # Default similarity threshold
    max_similar_memories: int = 10
    max_llm_context_memories: int = 5
    processing_timeout_seconds: int = 60
    replace_similarity_threshold: float = 0.9  # Higher threshold for replacement safety
    enabled: bool = True  # Can be disabled if needed


@dataclass
class ConsolidationResult:
    """Result of memory consolidation analysis."""
    action: ConsolidationAction
    memories_to_remove: List[str] = field(default_factory=list)
    memories_to_update: List[Dict[str, Any]] = field(default_factory=list)
    new_memory_content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""


@dataclass
class MemoryAnalysisContext:
    """Context for LLM memory analysis."""
    new_memory: str
    similar_memories: List[Dict[str, Any]]  # List of similar memory dicts
    area: str
    timestamp: str
    existing_metadata: Dict[str, Any]


class MemoryConsolidator:
    """
    Intelligent memory consolidation system that uses LLM analysis to determine
    optimal memory organization and automatically consolidates related memories.
    """

    def __init__(self, config: Optional[ConsolidationConfig] = None):
        self.config = config or ConsolidationConfig()
        self.vector = get_vector()

    async def process_new_memory(
        self,
        new_memory: str,
        area: str = None,
        metadata: Dict[str, Any] = None
    ) -> dict:
        """
        Process a new memory through the intelligent consolidation pipeline.

        Args:
            new_memory: The new memory content to process
            area: Memory area (MAIN, FRAGMENTS, SOLUTIONS, INSTRUMENTS)
            metadata: Initial metadata for the memory

        Returns:
            dict: {"success": bool, "memory_ids": [str, ...]}
        """
        if not self.config.enabled:
            # Consolidation disabled - just save directly
            return await self._save_directly(new_memory, area, metadata or {})

        try:
            # Start processing with timeout
            processing_task = asyncio.create_task(
                self._process_memory_with_consolidation(new_memory, area, metadata or {})
            )

            result = await asyncio.wait_for(
                processing_task,
                timeout=self.config.processing_timeout_seconds
            )
            return result

        except asyncio.TimeoutError:
            # Timeout - save directly without consolidation
            print("  ⚠️ Consolidation timeout, saving directly")
            return await self._save_directly(new_memory, area, metadata or {})

        except Exception as e:
            # Error - save directly without consolidation
            print(f"  ⚠️ Consolidation error: {e}, saving directly")
            return await self._save_directly(new_memory, area, metadata or {})

    async def _save_directly(
        self,
        new_memory: str,
        area: str = None,
        metadata: Dict[str, Any] = None
    ) -> dict:
        """Save memory directly without consolidation."""
        # Classify area if not provided
        if not area:
            area_enum = classify_memory_area(new_memory, metadata)
            area = area_enum.value

        # Add area to metadata (ensure no None values)
        if metadata is None:
            metadata = {}
        metadata["area"] = area or "MAIN"
        metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Remove any None values from metadata
        metadata = {k: v for k, v in metadata.items() if v is not None}

        # Save to vector DB
        try:
            # Use vector memory's add_message or create a generic add method
            # For now, we'll add it as a generic document
            doc_id = self.vector.add_message(
                session_id=metadata.get("session_id", "default"),
                role="system",  # System memory
                content=new_memory,
                domain=metadata.get("domain"),
                metadata=metadata
            )
            return {"success": True, "memory_ids": [doc_id]}
        except Exception as e:
            print(f"  ⚠️ Direct save error: {e}")
            return {"success": False, "memory_ids": []}

    async def _process_memory_with_consolidation(
        self,
        new_memory: str,
        area: str = None,
        metadata: Dict[str, Any] = None
    ) -> dict:
        """Process memory with consolidation logic."""
        # Step 1: Classify area if not provided
        if not area:
            area_enum = classify_memory_area(new_memory, metadata)
            area = area_enum.value

        # Step 2: Find similar memories
        similar_memories = await self._find_similar_memories(new_memory, area)

        # If no similar memories, save directly
        if not similar_memories:
            return await self._save_directly(new_memory, area, metadata or {})

        # Step 3: Analyze with LLM
        analysis_context = MemoryAnalysisContext(
            new_memory=new_memory,
            similar_memories=similar_memories,
            area=area,
            timestamp=datetime.now(timezone.utc).isoformat(),
            existing_metadata=metadata or {}
        )

        consolidation_result = await self._analyze_memory_consolidation(analysis_context)

        # Step 4: Apply consolidation
        if consolidation_result.action == ConsolidationAction.SKIP:
            return await self._save_directly(new_memory, area, metadata or {})

        memory_ids = await self._apply_consolidation_result(
            consolidation_result,
            area,
            metadata or {},
            new_memory
        )

        return {"success": bool(memory_ids), "memory_ids": memory_ids}

    async def _find_similar_memories(
        self,
        new_memory: str,
        area: str
    ) -> List[Dict[str, Any]]:
        """Find similar memories using semantic search."""
        try:
            # Search for similar memories in vector DB
            results = self.vector.search(
                query=new_memory,
                n_results=self.config.max_similar_memories
            )

            # Filter by area if possible
            similar = []
            for r in results:
                meta = r.get("metadata", {})
                # Check if area matches (if stored in metadata)
                if not meta.get("area") or meta.get("area") == area:
                    similar.append({
                        "id": meta.get("id", ""),
                        "content": r.get("content", ""),
                        "metadata": meta,
                        "distance": r.get("distance", 1.0)
                    })

            # Limit to max context for LLM
            return similar[:self.config.max_llm_context_memories]

        except Exception as e:
            print(f"  ⚠️ Similarity search error: {e}")
            return []

    async def _analyze_memory_consolidation(
        self,
        context: MemoryAnalysisContext
    ) -> ConsolidationResult:
        """Use LLM to analyze memory consolidation options."""
        try:
            from app.llm.client import OllamaClient
            llm = OllamaClient()

            # Prepare similar memories text
            similar_memories_text = ""
            for i, mem in enumerate(context.similar_memories):
                timestamp = mem.get("metadata", {}).get("timestamp", "unknown")
                mem_id = mem.get("id", f"mem_{i}")
                content = mem.get("content", "")
                similar_memories_text += f"ID: {mem_id}\nTimestamp: {timestamp}\nContent: {content}\n\n"

            # Build prompt for LLM analysis
            prompt = f"""Analyze whether this new memory should be consolidated with existing similar memories.

NEW MEMORY:
{context.new_memory}

EXISTING SIMILAR MEMORIES:
{similar_memories_text}

AREA: {context.area}

Determine the best action:
- MERGE: Combine new memory with existing ones into a single consolidated memory
- REPLACE: New memory supersedes existing ones (only if very similar, >90% match)
- UPDATE: Update existing memory with new information
- KEEP_SEPARATE: Keep as separate memories (different enough)
- SKIP: Don't save this memory (duplicate or low value)

Return JSON only:
{{
  "action": "merge|replace|update|keep_separate|skip",
  "memories_to_remove": ["id1", "id2"] (if merge/replace),
  "memories_to_update": [{{"id": "id3", "updated_content": "..."}}] (if update),
  "new_memory_content": "consolidated content" (if merge/replace),
  "reasoning": "brief explanation"
}}

JSON only, no explanation:"""

            response = llm.generate(prompt, timeout=30, stream=False).strip()

            # Parse LLM response
            result_json = self._parse_json_response(response)

            if not isinstance(result_json, dict):
                raise ValueError("LLM response is not a valid JSON object")

            # Parse consolidation result
            action_str = result_json.get("action", "skip")
            try:
                action = ConsolidationAction(action_str.lower())
            except ValueError:
                action = ConsolidationAction.SKIP

            # Determine appropriate fallback for new_memory_content
            if action in [ConsolidationAction.MERGE, ConsolidationAction.REPLACE]:
                default_content = ""
            else:
                default_content = context.new_memory

            return ConsolidationResult(
                action=action,
                memories_to_remove=result_json.get("memories_to_remove", []),
                memories_to_update=result_json.get("memories_to_update", []),
                new_memory_content=result_json.get("new_memory_content", default_content),
                metadata=result_json.get("metadata", {}),
                reasoning=result_json.get("reasoning", "")
            )

        except Exception as e:
            print(f"  ⚠️ LLM consolidation analysis failed: {e}")
            # Fallback: skip consolidation
            return ConsolidationResult(
                action=ConsolidationAction.SKIP,
                reasoning=f"Analysis failed: {str(e)}"
            )

    def _parse_json_response(self, response: str) -> dict:
        """Parse JSON from LLM response, handling common issues."""
        import re

        # Remove code fences
        clean_response = re.sub(r'^```json\s*', '', response, flags=re.MULTILINE)
        clean_response = re.sub(r'^```\s*', '', clean_response, flags=re.MULTILINE)
        clean_response = re.sub(r'\s*```$', '', clean_response)
        clean_response = re.sub(r'//.*$', '', clean_response, flags=re.MULTILINE)  # Remove comments

        # Try to extract JSON
        json_match = re.search(r'\{.*\}', clean_response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(), strict=False)
            except json.JSONDecodeError:
                pass

        # Fallback: return empty dict
        return {}

    async def _apply_consolidation_result(
        self,
        result: ConsolidationResult,
        area: str,
        original_metadata: Dict[str, Any],
        new_memory: str
    ) -> List[str]:
        """Apply the consolidation decisions to the memory database."""
        try:
            memory_ids = []

            if result.action == ConsolidationAction.MERGE:
                # Merge: Create new consolidated memory, remove old ones
                consolidated_content = result.new_memory_content or new_memory
                consolidated_metadata = original_metadata.copy()
                consolidated_metadata["area"] = area or "MAIN"
                consolidated_metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
                # Convert list to JSON string for ChromaDB compatibility
                if result.memories_to_remove:
                    consolidated_metadata["consolidated_from"] = json.dumps(result.memories_to_remove)
                
                # Remove any None values from metadata
                consolidated_metadata = {k: v for k, v in consolidated_metadata.items() if v is not None}

                # Save consolidated memory
                doc_id = self.vector.add_message(
                    session_id=consolidated_metadata.get("session_id", "default"),
                    role="system",
                    content=consolidated_content,
                    domain=consolidated_metadata.get("domain"),
                    metadata=consolidated_metadata
                )
                memory_ids.append(doc_id)

                # Note: Vector DB doesn't have easy delete, so we mark as removed in metadata
                # In a full implementation, you'd delete from vector DB here

            elif result.action == ConsolidationAction.REPLACE:
                # Replace: Remove old memories, save new one
                consolidated_metadata = original_metadata.copy()
                consolidated_metadata["area"] = area or "MAIN"
                consolidated_metadata["timestamp"] = datetime.now(timezone.utc).isoformat()
                # Convert list to JSON string for ChromaDB compatibility
                if result.memories_to_remove:
                    consolidated_metadata["replaced"] = json.dumps(result.memories_to_remove)
                
                # Remove any None values from metadata
                consolidated_metadata = {k: v for k, v in consolidated_metadata.items() if v is not None}

                doc_id = self.vector.add_message(
                    session_id=consolidated_metadata.get("session_id", "default"),
                    role="system",
                    content=result.new_memory_content or new_memory,
                    domain=consolidated_metadata.get("domain"),
                    metadata=consolidated_metadata
                )
                memory_ids.append(doc_id)

            elif result.action == ConsolidationAction.UPDATE:
                # Update: Update existing memories
                for update_info in result.memories_to_update:
                    # Note: Vector DB update is complex, for now we just save new version
                    # In full implementation, you'd update the existing document
                    pass

                # Also save new memory
                doc_id = self._save_directly(new_memory, area, original_metadata)
                if doc_id.get("memory_ids"):
                    memory_ids.extend(doc_id["memory_ids"])

            elif result.action == ConsolidationAction.KEEP_SEPARATE:
                # Keep separate: Just save new memory
                doc_id = await self._save_directly(new_memory, area, original_metadata)
                if doc_id.get("memory_ids"):
                    memory_ids.extend(doc_id["memory_ids"])

            return memory_ids

        except Exception as e:
            print(f"  ⚠️ Consolidation application error: {e}")
            return []


# Singleton
_consolidator_instance = None

def get_memory_consolidator(config: Optional[ConsolidationConfig] = None) -> MemoryConsolidator:
    """Get or create memory consolidator instance."""
    global _consolidator_instance
    if _consolidator_instance is None:
        _consolidator_instance = MemoryConsolidator(config)
    return _consolidator_instance
