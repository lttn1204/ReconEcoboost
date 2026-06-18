"""Analysis modules — AI-facing stages (summary, classification, attack planning).

These are pipeline modules like any other (they subclass BaseModule and declare
requires/produces), but they consume the AI provider abstraction instead of an
external tool. No AI logic is implemented in the skeleton.
"""
