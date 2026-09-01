"""Behavior engine — the reasoning layer for stateful, low-false-positive testing.

Modules:
- state: SessionState and StateHistory (track authentication state)
- transitions: explicit state transitions the engine can observe
- hypotheses: declarative security invariants to test
- planner: turn a Hypothesis into a Test Plan
- differential: compare baseline vs controlled responses
- model: the BehaviorModel that ties everything together
"""
from redveil.behavior.state import SessionState, State, StateHistory
from redveil.behavior.transitions import Transition, TransitionKind, DEFAULT_TRANSITIONS
from redveil.behavior.hypotheses import Hypothesis, InvariantKind
from redveil.behavior.planner import TestPlan, TestStep, plan_for_hypothesis
from redveil.behavior.differential import DifferentialResult, compute_differential
from redveil.behavior.model import BehaviorModel

__all__ = [
    "SessionState", "State", "StateHistory",
    "Transition", "TransitionKind", "DEFAULT_TRANSITIONS",
    "Hypothesis", "InvariantKind",
    "TestPlan", "TestStep", "plan_for_hypothesis",
    "DifferentialResult", "compute_differential",
    "BehaviorModel",
]
