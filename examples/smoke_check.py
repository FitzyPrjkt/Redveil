"""Example check plugin: prints 'hello' when run. Used to verify the plugin
system is wired correctly. Remove or replace before shipping Phase 1."""

from __future__ import annotations

import asyncio

from redveil.config import SafetyProfile
from redveil.plugins.base import Check, CheckCategory, CheckMeta


class HelloCheck(Check):
    meta = CheckMeta(
        id="hello-smoke",
        name="Hello Smoke Check",
        category=CheckCategory.DISCLOSURE,
        safety_profile=SafetyProfile.PASSIVE,
        description="Trivial check that emits a FINDING_DETECTED to verify the pipeline.",
    )

    async def discover(self, ctx):
        await asyncio.sleep(0)
        return [{"smoke": True}]


if __name__ == "__main__":
    c = HelloCheck()
    print(f"id={c.id}  name={c.name}  category={c.category}  profile={c.safety_profile.value}")