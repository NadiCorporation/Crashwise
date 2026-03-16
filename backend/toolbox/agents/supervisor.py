"""LangGraph Supervisor Agent for Autonomous Crash Analysis.

This module implements a ReAct-style supervisor that orchestrates crash
triage activities (triage, dedup, minimize) with LLM-based decision making.

The supervisor uses a state machine to:
1. Analyze crash state
2. Decide next action via LLM reasoning
3. Execute chosen activity
4. Update state and repeat until terminal state

Usage:
    from toolbox.agents.supervisor import CrashSupervisor

    supervisor = CrashSupervisor()
    result = await supervisor.run(crash_data={"crash_dir": "/path/to/crashes"})
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, TypedDict
from enum import Enum

logger = logging.getLogger(__name__)

# LiteLLM proxy configuration (same as activities)
LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://llm-proxy:4000/v1")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", "sk-no-key-needed")

# LangGraph imports (graceful fallback if not installed)
try:
    from langgraph.graph import StateGraph, END
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_openai import ChatOpenAI

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    logger.warning("LangGraph not installed. Supervisor will use fallback mode.")


class SupervisorAction(str, Enum):
    """Available actions the supervisor can take."""

    # Crash triage actions
    TRIAGE = "triage"
    DEDUP = "dedup"
    MINIMIZE = "minimize"
    REPORT = "report"
    END = "end"

    # Coverage stall handling actions
    MUTATE_SEEDS = "mutate_seeds"
    CHANGE_FUZZER_PARAMS = "change_fuzzer_params"
    NEW_HARNESS_VARIANT = "new_harness_variant"
    ADD_DICTIONARY = "add_dictionary"
    SWITCH_FUZZER = "switch_fuzzer"
    CONTINUE_MONITORING = "continue_monitoring"


class CrashState(TypedDict):
    """State passed between supervisor nodes."""

    # Input
    crash_dir: str
    target_binary: Optional[str]

    # Collected data
    crash_files: List[Dict[str, Any]]
    parsed_crashes: List[Dict[str, Any]]

    # Analysis results
    triage_result: Optional[Dict[str, Any]]
    dedup_result: Optional[Dict[str, Any]]
    minimization_result: Optional[Dict[str, Any]]
    report_result: Optional[Dict[str, Any]]

    # Coverage tracking for stall detection
    coverage_history: List[
        Dict[str, float]
    ]  # [{"time": ..., "edges": ..., "percent": ...}]
    stall_detected: bool
    stall_count: int
    stall_actions_taken: List[str]
    stall_info: Optional[Dict[str, Any]]

    # Supervisor state
    iteration: int
    max_iterations: int
    decision_history: List[Dict[str, Any]]
    current_thought: Optional[str]
    next_action: Optional[str]
    final_decision: Optional[str]
    status: str  # "running", "completed", "error"


def create_initial_state(
    crash_dir: str,
    target_binary: Optional[str] = None,
    coverage_history: Optional[List[Dict[str, float]]] = None,
) -> CrashState:
    """Create initial state for supervisor."""
    return CrashState(
        crash_dir=crash_dir,
        target_binary=target_binary,
        crash_files=[],
        parsed_crashes=[],
        triage_result=None,
        dedup_result=None,
        minimization_result=None,
        report_result=None,
        # Coverage tracking
        coverage_history=coverage_history or [],
        stall_detected=False,
        stall_count=0,
        stall_actions_taken=[],
        stall_info=None,
        # Supervisor state
        iteration=0,
        max_iterations=5,
        decision_history=[],
        current_thought=None,
        next_action=None,
        final_decision=None,
        status="running",
    )


def detect_stall_from_history(
    coverage_history: List[Dict[str, float]],
    threshold: int = 10,
    min_improvement: int = 5,
) -> Dict[str, Any]:
    """
    Detect coverage stall from history.

    Args:
        coverage_history: List of coverage measurements over time
        threshold: Number of measurements to consider for stall detection
        min_improvement: Minimum edges improvement to not be considered stalled

    Returns:
        Dictionary with stall detection results
    """
    if len(coverage_history) < threshold:
        return {
            "stalled": False,
            "reason": f"insufficient_data ({len(coverage_history)} < {threshold})",
        }

    recent = coverage_history[-threshold:]
    edges = [h.get("edges", 0) for h in recent]

    max_edges = max(edges)
    min_edges = min(edges)
    improvement = max_edges - min_edges

    # Check if edges are flat
    if improvement < min_improvement:
        return {
            "stalled": True,
            "stall_count": threshold,
            "max_edges": max_edges,
            "min_edges": min_edges,
            "improvement": improvement,
            "reason": f"Only {improvement} new edges in last {threshold} measurements",
            "suggested_actions": [
                {
                    "action": "mutate_seeds",
                    "description": "Apply seed mutation strategies",
                    "priority": 1,
                },
                {
                    "action": "change_fuzzer_params",
                    "description": "Adjust AFL mutation parameters",
                    "priority": 2,
                },
                {
                    "action": "new_harness_variant",
                    "description": "Generate alternative harness",
                    "priority": 3,
                },
                {
                    "action": "add_dictionary",
                    "description": "Add dictionary entries",
                    "priority": 4,
                },
                {
                    "action": "switch_fuzzer",
                    "description": "Try different fuzzer",
                    "priority": 5,
                },
            ],
        }

    return {"stalled": False, "improvement": improvement, "max_edges": max_edges}


# ============================================================================
# LangGraph Supervisor Implementation
# ============================================================================


class CrashSupervisor:
    """
    Autonomous crash analysis supervisor using LangGraph.

    Orchestrates crash triage activities with LLM-based decision making.
    Uses ReAct-style prompting: think → decide action → observe → repeat.
    """

    def __init__(
        self,
        model: str = "opencode/minimax-m2.5",  # Faster, cheaper for iterations
        primary_model: str = "opencode/glm-5",  # For complex analysis
        max_iterations: int = 5,
    ):
        self.model = model
        self.primary_model = primary_model
        self.max_iterations = max_iterations
        self._llm = None
        self._graph = None

    def _get_llm(self):
        """Lazy-load LLM client."""
        if self._llm is None:
            if not LANGGRAPH_AVAILABLE:
                raise RuntimeError("LangGraph not installed. Cannot create supervisor.")
            self._llm = ChatOpenAI(
                model=self.model,
                base_url=LITELLM_BASE_URL,
                api_key=LITELLM_API_KEY,
                temperature=0.3,
            )
        return self._llm

    def _build_graph(self):
        """Build the LangGraph state machine."""
        if self._graph is not None:
            return self._graph

        if not LANGGRAPH_AVAILABLE:
            raise RuntimeError("LangGraph not installed.")

        # Create state graph
        workflow = StateGraph(CrashState)

        # Add nodes
        workflow.add_node("supervisor", self._supervisor_node)
        workflow.add_node("collect", self._collect_node)
        workflow.add_node("parse", self._parse_node)
        workflow.add_node("triage", self._triage_node)
        workflow.add_node("dedup", self._dedup_node)
        workflow.add_node("minimize", self._minimize_node)
        workflow.add_node("report", self._report_node)
        workflow.add_node("finalize", self._finalize_node)

        # Set entry point
        workflow.set_entry_point("collect")

        # Add edges
        workflow.add_edge("collect", "parse")
        workflow.add_edge("parse", "supervisor")

        # Conditional routing from supervisor
        workflow.add_conditional_edges(
            "supervisor",
            self._route_from_supervisor,
            {
                "triage": "triage",
                "dedup": "dedup",
                "minimize": "minimize",
                "report": "report",
                "end": "finalize",
            },
        )

        # After each action, return to supervisor for next decision
        workflow.add_edge("triage", "supervisor")
        workflow.add_edge("dedup", "supervisor")
        workflow.add_edge("minimize", "supervisor")
        workflow.add_edge("report", "supervisor")
        workflow.add_edge("finalize", END)

        self._graph = workflow.compile()
        return self._graph

    async def run(
        self,
        crash_dir: str,
        target_binary: Optional[str] = None,
        enable_triage: bool = True,
        enable_minimization: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the supervisor to analyze crashes autonomously.

        Args:
            crash_dir: Directory containing crash files
            target_binary: Optional path to target binary for minimization
            enable_triage: Whether to run LLM triage
            enable_minimization: Whether to run crash minimization

        Returns:
            Final state with all analysis results
        """
        if not LANGGRAPH_AVAILABLE:
            logger.warning("LangGraph not available, using fallback mode")
            return await self._fallback_run(
                crash_dir=crash_dir,
                target_binary=target_binary,
                enable_triage=enable_triage,
                enable_minimization=enable_minimization,
            )

        # Initialize state
        initial_state = create_initial_state(crash_dir, target_binary)
        initial_state["max_iterations"] = self.max_iterations

        # Build and invoke graph
        graph = self._build_graph()

        logger.info(f"Starting CrashSupervisor for: {crash_dir}")

        try:
            # LangGraph invoke
            final_state = await graph.ainvoke(initial_state)

            logger.info(f"Supervisor completed: {final_state.get('status')}")
            return final_state

        except Exception as e:
            logger.error(f"Supervisor error: {e}")
            return {
                "status": "error",
                "error": str(e),
                "crash_dir": crash_dir,
            }

    # ========================================================================
    # Node Implementations
    # ========================================================================

    async def _supervisor_node(self, state: CrashState) -> CrashState:
        """
        LLM-powered decision node.

        Analyzes current state and decides next action.
        Uses ReAct-style reasoning.
        """
        state["iteration"] += 1
        logger.info(
            f"Supervisor iteration {state['iteration']}/{state['max_iterations']}"
        )

        # Check iteration limit
        if state["iteration"] > state["max_iterations"]:
            logger.warning("Max iterations reached, ending")
            state["next_action"] = "end"
            state["final_decision"] = "max_iterations_reached"
            return state

        # Build context for LLM
        context = self._build_supervisor_context(state)

        # Get LLM decision
        llm = self._get_llm()

        system_prompt = """You are CrashWise Supervisor — an autonomous security research agent.
Goal: analyze fuzz crashes, triage them intelligently, minimize PoCs, and report findings.

You make decisions based on current crash analysis state.
Output ONLY valid JSON, no markdown, no explanation.

Available actions:
CRASH TRIAGE:
- triage: run LLM triage for vulnerability assessment
- dedup: check if crash is duplicate of known issue  
- minimize: minimize crash PoC using afl-tmin (if target_binary available)
- report: create GitHub issue for high-severity new crash (exploitability >= 7, not duplicate)
- end: complete analysis

COVERAGE STALL HANDLING (if stall_detected=true):
- mutate_seeds: apply mutation strategies to existing seeds
- change_fuzzer_params: adjust AFL parameters (increase mutations, enable MOpt)
- new_harness_variant: generate alternative harness from different entry point
- add_dictionary: create/expand AFL dictionary with interesting tokens
- switch_fuzzer: try different fuzzer (honggfuzz, libFuzzer)
- continue_monitoring: no action needed, keep fuzzing

Decision criteria:
CRASH ANALYSIS:
1. New crash without triage → triage
2. After triage, check for duplicates → dedup
3. If unique and high-severity (score >= 7) and target_binary → minimize
4. After minimization, if unique and high-severity (score >= 7) → report
5. If duplicate or low-severity → end
6. If all analysis complete → end

STALL HANDLING:
7. If stall_detected=true and coverage flat:
   - Choose one stall action based on context
   - Prioritize: new_harness_variant > mutate_seeds > add_dictionary
   - Do not repeat actions already in stall_actions_taken
8. If all stall actions tried → continue_monitoring

Output JSON format:
{"thought": "...", "action": "triage|dedup|minimize|report|end|mutate_seeds|...", "reason": "..."}"""

        user_message = f"""Current crash analysis state:
{json.dumps(context, indent=2)}

What is the next action? Output ONLY JSON."""

        try:
            response = await llm.ainvoke(
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_message),
                ]
            )

            content = response.content.strip()

            # Parse JSON response
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            decision = json.loads(content)

            state["current_thought"] = decision.get("thought", "")
            state["next_action"] = decision.get("action", "end")

            # Record decision
            state["decision_history"].append(
                {
                    "iteration": state["iteration"],
                    "thought": state["current_thought"],
                    "action": state["next_action"],
                    "reason": decision.get("reason", ""),
                }
            )

            logger.info(
                f"Supervisor decision: {state['next_action']} - {state['current_thought']}"
            )

        except Exception as e:
            logger.error(f"LLM decision failed: {e}")
            state["next_action"] = "end"
            state["final_decision"] = f"llm_error: {e}"

        return state

    async def _collect_node(self, state: CrashState) -> CrashState:
        """Collect crash files from directory."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            collect_crash_data,
        )

        logger.info(f"Collecting crashes from: {state['crash_dir']}")

        result = await collect_crash_data(state["crash_dir"], {"crash_type": "auto"})

        state["crash_files"] = result.get("crash_files", [])
        state["status"] = result.get("status", "error")

        logger.info(f"Collected {len(state['crash_files'])} crash files")
        return state

    async def _parse_node(self, state: CrashState) -> CrashState:
        """Parse crash reports."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            parse_crash_reports,
        )

        logger.info("Parsing crash reports")

        collect_result = {
            "crash_files": state["crash_files"],
            "options": {"crash_type": "auto"},
        }

        result = await parse_crash_reports(collect_result)

        state["parsed_crashes"] = result.get("parsed_crashes", [])

        logger.info(f"Parsed {len(state['parsed_crashes'])} crashes")
        return state

    async def _triage_node(self, state: CrashState) -> CrashState:
        """Run LLM triage on crashes."""
        from toolbox.workflows.crash_triage_pipeline.activities import llm_crash_triage

        if not state["parsed_crashes"]:
            logger.warning("No crashes to triage")
            return state

        logger.info("Running LLM triage")

        result = await llm_crash_triage({"parsed_crashes": state["parsed_crashes"]})

        state["triage_result"] = result

        logger.info(
            f"Triage complete: real_bug={result.get('is_real_bug')}, "
            f"score={result.get('exploitability_score')}"
        )
        return state

    async def _dedup_node(self, state: CrashState) -> CrashState:
        """Check crash for duplicates."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            check_crash_duplicate,
        )

        if not state["parsed_crashes"]:
            logger.warning("No crashes to dedup")
            return state

        logger.info("Checking for duplicates")

        # Dedup each crash
        for crash in state["parsed_crashes"]:
            crash_data = {
                "stack_hash": crash.get("crash_hash"),
                "stack_trace": crash.get("stack_trace", []),
                "raw_content": crash.get("raw_content", ""),
                "error_type": crash.get("error_type"),
                "llm_analysis": state.get("triage_result"),
            }

            result = await check_crash_duplicate(crash_data)
            crash["is_duplicate"] = result.get("is_duplicate", False)
            crash["similar_crashes"] = result.get("similar_crashes", [])

        state["dedup_result"] = {"status": "complete"}

        logger.info("Dedup complete")
        return state

    async def _minimize_node(self, state: CrashState) -> CrashState:
        """Minimize crash PoC using afl-tmin."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            minimize_crash_poc,
        )

        if not state["target_binary"]:
            logger.warning("No target binary for minimization")
            return state

        if not state["parsed_crashes"]:
            logger.warning("No crashes to minimize")
            return state

        # Check if high severity
        triage = state.get("triage_result", {})
        if triage.get("exploitability_score", 0) < 5:
            logger.info("Low exploitability, skipping minimization")
            return state

        logger.info("Minimizing crash PoC")

        crash = state["parsed_crashes"][0]  # Minimize first crash
        crash_file = crash.get("source_file")

        if not crash_file:
            logger.warning("No crash file path found")
            return state

        result = await minimize_crash_poc(
            {
                "crash_file_path": crash_file,
                "target_binary": state["target_binary"],
                "llm_analysis": state.get("triage_result"),
            }
        )

        state["minimization_result"] = result

        logger.info(f"Minimization complete: {result.get('status')}")
        return state

    async def _report_node(self, state: CrashState) -> CrashState:
        """Create GitHub issue for high-severity crash."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            create_github_issue,
        )

        if not state["parsed_crashes"]:
            logger.warning("No crashes to report")
            return state

        # Check conditions for reporting
        triage = state.get("triage_result", {})
        is_real_bug = triage.get("is_real_bug", False)
        exploitability = triage.get("exploitability_score", 0)

        if not is_real_bug:
            logger.info("Not a real bug, skipping report")
            state["report_result"] = {"status": "skipped", "reason": "not_real_bug"}
            return state

        if exploitability < 7:
            logger.info(f"Low exploitability ({exploitability}), skipping report")
            state["report_result"] = {
                "status": "skipped",
                "reason": "low_exploitability",
            }
            return state

        crash = state["parsed_crashes"][0]

        logger.info("Creating GitHub issue for high-severity crash")

        result = await create_github_issue(
            triage_result=triage,
            crash_data={
                "source_file": crash.get("source_file"),
                "stack_trace": crash.get("stack_trace", []),
                "crash_hash": crash.get("crash_hash"),
                "is_duplicate": crash.get("is_duplicate", False),
                "error_type": crash.get("error_type"),
            },
        )

        state["report_result"] = result

        if result.get("status") == "created":
            logger.info(f"GitHub issue created: {result.get('issue_url')}")
        else:
            logger.warning(f"GitHub issue creation failed: {result.get('error')}")

        return state

    async def _finalize_node(self, state: CrashState) -> CrashState:
        """Generate final report."""
        logger.info("Finalizing crash analysis")

        state["status"] = "completed"

        # Generate summary
        summary = {
            "crash_dir": state["crash_dir"],
            "total_crashes": len(state["parsed_crashes"]),
            "triage": state.get("triage_result"),
            "duplicates": [c for c in state["parsed_crashes"] if c.get("is_duplicate")],
            "minimization": state.get("minimization_result"),
            "decisions": state["decision_history"],
            "final_status": state["status"],
        }

        state["final_decision"] = json.dumps(summary, indent=2)

        logger.info(f"Analysis complete. Status: {state['status']}")
        return state

    # ========================================================================
    # Routing Logic
    # ========================================================================

    def _route_from_supervisor(self, state: CrashState) -> str:
        """Determine next node based on supervisor decision."""
        action = state.get("next_action", "end")

        # Validate action
        if action not in ["triage", "dedup", "minimize", "report", "end"]:
            logger.warning(f"Invalid action '{action}', defaulting to end")
            return "end"

        return action

    def _build_supervisor_context(self, state: CrashState) -> Dict[str, Any]:
        """Build context summary for LLM decision."""
        context = {
            "iteration": state["iteration"],
            "max_iterations": state["max_iterations"],
            "total_crashes": len(state["parsed_crashes"]),
            "has_triage": state["triage_result"] is not None,
            "has_dedup": state["dedup_result"] is not None,
            "has_minimization": state["minimization_result"] is not None,
            "triage_summary": {
                "is_real_bug": state["triage_result"].get("is_real_bug")
                if state.get("triage_result")
                else None,
                "exploitability_score": state["triage_result"].get(
                    "exploitability_score"
                )
                if state.get("triage_result")
                else None,
                "vulnerability_class": state["triage_result"].get("vulnerability_class")
                if state.get("triage_result")
                else None,
            },
            "duplicate_count": len(
                [c for c in state["parsed_crashes"] if c.get("is_duplicate")]
            ),
            "has_target_binary": state["target_binary"] is not None,
            "previous_actions": [d["action"] for d in state["decision_history"]],
        }

        # Add stall information if available
        if state.get("coverage_history"):
            stall_info = detect_stall_from_history(state["coverage_history"])
            context["stall_detected"] = stall_info.get("stalled", False)
            context["stall_info"] = stall_info
            context["stall_actions_taken"] = state.get("stall_actions_taken", [])
            context["coverage_edges"] = stall_info.get("max_edges", 0)
            context["coverage_improvement"] = stall_info.get("improvement", 0)

        return context

    async def _handle_stall_node(self, state: CrashState) -> CrashState:
        """Handle coverage stall by deciding on corrective action."""
        import random

        logger.info("Handling coverage stall")

        stall_info = state.get("stall_info", {})
        suggested = stall_info.get("suggested_actions", [])

        # Get LLM recommendation for stall action
        llm = self._get_llm()

        system_prompt = """You are a fuzzing optimization expert.
Given a coverage stall, choose the best action to regain coverage progress.
Output ONLY JSON: {"action": "chosen_action", "reason": "why this action"}"""

        user_message = f"""Coverage Stall Detected:
- Max edges: {stall_info.get("max_edges", 0)}
- Improvement: {stall_info.get("improvement", 0)} edges in last {stall_info.get("stall_count", 10)} measurements
- Actions already tried: {state.get("stall_actions_taken", [])}
- Suggested actions: {suggested}

Choose the best action to try next.
If all actions tried, choose "continue_monitoring"."""

        try:
            response = await llm.ainvoke(
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=user_message),
                ]
            )

            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            decision = json.loads(content)
            action = decision.get("action", "continue_monitoring")

            # Record stall action
            state["stall_actions_taken"].append(action)
            state["next_action"] = action
            state["stall_count"] += 1

            logger.info(f"Stall handler chose: {action} - {decision.get('reason', '')}")

        except Exception as e:
            logger.error(f"Stall handler LLM failed: {e}")
            # Fallback: choose first suggested action not yet tried
            for suggestion in suggested:
                action = suggestion.get("action")
                if action not in state.get("stall_actions_taken", []):
                    state["next_action"] = action
                    state["stall_actions_taken"].append(action)
                    break
            else:
                state["next_action"] = "continue_monitoring"

        return state

    # ========================================================================
    # Fallback Mode (when LangGraph not available)
    # ========================================================================

    async def _fallback_run(
        self,
        crash_dir: str,
        target_binary: Optional[str] = None,
        enable_triage: bool = True,
        enable_minimization: bool = False,
    ) -> Dict[str, Any]:
        """Simple sequential fallback when LangGraph is not available."""
        from toolbox.workflows.crash_triage_pipeline.activities import (
            collect_crash_data,
            parse_crash_reports,
            llm_crash_triage,
            check_crash_duplicate,
        )

        logger.info("Using fallback sequential mode (LangGraph not available)")

        state = create_initial_state(crash_dir, target_binary)

        # Collect
        collect_result = await collect_crash_data(crash_dir, {"crash_type": "auto"})
        state["crash_files"] = collect_result.get("crash_files", [])

        # Parse
        parse_result = await parse_crash_reports(collect_result)
        state["parsed_crashes"] = parse_result.get("parsed_crashes", [])

        # Triage
        if enable_triage and state["parsed_crashes"]:
            triage_result = await llm_crash_triage(
                {"parsed_crashes": state["parsed_crashes"]}
            )
            state["triage_result"] = triage_result

            # Dedup
            for crash in state["parsed_crashes"]:
                crash_data = {
                    "stack_hash": crash.get("crash_hash"),
                    "stack_trace": crash.get("stack_trace", []),
                    "raw_content": crash.get("raw_content", ""),
                    "error_type": crash.get("error_type"),
                    "llm_analysis": triage_result,
                }
                dup_result = await check_crash_duplicate(crash_data)
                crash["is_duplicate"] = dup_result.get("is_duplicate", False)

        state["status"] = "completed"
        return dict(state)


# ============================================================================
# Convenience Entry Point
# ============================================================================


async def run_supervisor(
    crash_dir: str,
    target_binary: Optional[str] = None,
    model: str = "opencode/minimax-m2.5",
    max_iterations: int = 5,
) -> Dict[str, Any]:
    """
    Convenience function to run the crash supervisor.

    Args:
        crash_dir: Directory containing crash files
        target_binary: Optional path to target binary for minimization
        model: LLM model for supervisor decisions
        max_iterations: Maximum decision iterations

    Returns:
        Analysis result dictionary
    """
    supervisor = CrashSupervisor(model=model, max_iterations=max_iterations)
    return await supervisor.run(
        crash_dir=crash_dir,
        target_binary=target_binary,
    )
