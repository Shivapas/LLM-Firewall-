"""Sprint 24A: Red Teaming — Agentic Probe Suite Tests.

Covers:
- Tool call injection probes (unauthorized invocation, parameter tampering, hidden calls)
- Memory poisoning simulation probes (instruction injection, context poisoning, retrieval poisoning)
- Privilege escalation via agent context probes (role manipulation, scope expansion, system instruction manipulation)
- Multi-step attack chain probes (recon-inject-exfil, privilege escalation chains, social engineering, persistence)
- Runner integration with new probe categories
- Acceptance criteria validation
"""

import pytest


# ── 1. Tool Call Injection Probe Suite ──────────────────────────────────────


class TestToolCallInjectionProbeSuite:
    """Validate tool call injection probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        assert len(TOOL_CALL_INJECTION_PROBES) >= 25, (
            f"Expected 25+ tool call injection probes, got {len(TOOL_CALL_INJECTION_PROBES)}"
        )

    def test_probe_structure(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in TOOL_CALL_INJECTION_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        for probe in TOOL_CALL_INJECTION_PROBES:
            assert probe["category"] == "tool_call_injection", (
                f"Probe {probe['id']} has wrong category: {probe['category']}"
            )

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        ids = [p["id"] for p in TOOL_CALL_INJECTION_PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found in tool call injection probes"

    def test_unauthorized_tool_invocation_probes(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        probes = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "unauthorized_tool_invocation"]
        assert len(probes) >= 5, f"Expected 5+ unauthorized tool invocation probes, got {len(probes)}"

    def test_parameter_tampering_probes(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        probes = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "parameter_tampering"]
        assert len(probes) >= 5, f"Expected 5+ parameter tampering probes, got {len(probes)}"

    def test_hidden_tool_call_probes(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        probes = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "hidden_tool_call"]
        assert len(probes) >= 5, f"Expected 5+ hidden tool call probes, got {len(probes)}"

    def test_multi_tool_orchestration_probes(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        probes = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "multi_tool_orchestration"]
        assert len(probes) >= 3, f"Expected 3+ multi-tool orchestration probes, got {len(probes)}"

    def test_severity_values_valid(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        valid = {"critical", "high", "medium", "low"}
        for probe in TOOL_CALL_INJECTION_PROBES:
            assert probe["severity"] in valid, f"Probe {probe['id']} has invalid severity: {probe['severity']}"

    def test_payloads_non_empty(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        for probe in TOOL_CALL_INJECTION_PROBES:
            assert len(probe["payload"]) > 10, f"Probe {probe['id']} has too-short payload"

    def test_success_indicators_non_empty(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        for probe in TOOL_CALL_INJECTION_PROBES:
            assert len(probe["success_indicators"]) > 0, f"Probe {probe['id']} has no success indicators"

    def test_detects_unauthorized_tool_invocations(self):
        """Acceptance: probes detect unauthorized tool invocations and parameter tampering."""
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        unauthorized = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "unauthorized_tool_invocation"]
        tampering = [p for p in TOOL_CALL_INJECTION_PROBES if p["technique"] == "parameter_tampering"]
        assert len(unauthorized) >= 5, "Must have probes for unauthorized tool invocation detection"
        assert len(tampering) >= 5, "Must have probes for parameter tampering detection"
        # Verify probes target meaningful attack vectors
        all_payloads = " ".join(p["payload"] for p in unauthorized + tampering)
        assert "execute" in all_payloads.lower() or "call" in all_payloads.lower(), (
            "Probes should target tool execution/calling patterns"
        )


# ── 2. Memory Poisoning Probe Suite ────────────────────────────────────────


class TestMemoryPoisoningProbeSuite:
    """Validate memory poisoning simulation probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        assert len(MEMORY_POISONING_PROBES) >= 25, (
            f"Expected 25+ memory poisoning probes, got {len(MEMORY_POISONING_PROBES)}"
        )

    def test_probe_structure(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in MEMORY_POISONING_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        for probe in MEMORY_POISONING_PROBES:
            assert probe["category"] == "memory_poisoning", (
                f"Probe {probe['id']} has wrong category: {probe['category']}"
            )

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        ids = [p["id"] for p in MEMORY_POISONING_PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found in memory poisoning probes"

    def test_instruction_injection_probes(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        probes = [p for p in MEMORY_POISONING_PROBES if p["technique"] == "instruction_injection"]
        assert len(probes) >= 5, f"Expected 5+ instruction injection probes, got {len(probes)}"

    def test_context_window_poisoning_probes(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        probes = [p for p in MEMORY_POISONING_PROBES if p["technique"] == "context_window_poisoning"]
        assert len(probes) >= 5, f"Expected 5+ context window poisoning probes, got {len(probes)}"

    def test_retrieval_poisoning_probes(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        probes = [p for p in MEMORY_POISONING_PROBES if p["technique"] == "retrieval_poisoning"]
        assert len(probes) >= 5, f"Expected 5+ retrieval poisoning probes, got {len(probes)}"

    def test_agent_memory_manipulation_probes(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        probes = [p for p in MEMORY_POISONING_PROBES if p["technique"] == "agent_memory_manipulation"]
        assert len(probes) >= 5, f"Expected 5+ agent memory manipulation probes, got {len(probes)}"

    def test_severity_values_valid(self):
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        valid = {"critical", "high", "medium", "low"}
        for probe in MEMORY_POISONING_PROBES:
            assert probe["severity"] in valid, f"Probe {probe['id']} has invalid severity: {probe['severity']}"

    def test_identifies_instruction_like_content(self):
        """Acceptance: probes identify instruction-like content planted in agent memory stores."""
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        instruction_probes = [p for p in MEMORY_POISONING_PROBES if p["technique"] == "instruction_injection"]
        assert len(instruction_probes) >= 5, "Must have probes for instruction injection detection"
        # Verify probes contain instruction-like patterns
        for probe in instruction_probes:
            payload_lower = probe["payload"].lower()
            has_instruction = any(kw in payload_lower for kw in [
                "remember", "save", "store", "update", "add", "instruction",
                "override", "correction", "part 3", "feedback",
            ])
            assert has_instruction, (
                f"Probe {probe['id']} should contain instruction-like content for memory poisoning"
            )


# ── 3. Privilege Escalation Probe Suite ─────────────────────────────────────


class TestPrivilegeEscalationProbeSuite:
    """Validate privilege escalation via agent context probe suite."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        assert len(PRIVILEGE_ESCALATION_PROBES) >= 20, (
            f"Expected 20+ privilege escalation probes, got {len(PRIVILEGE_ESCALATION_PROBES)}"
        )

    def test_probe_structure(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in PRIVILEGE_ESCALATION_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        for probe in PRIVILEGE_ESCALATION_PROBES:
            assert probe["category"] == "privilege_escalation", (
                f"Probe {probe['id']} has wrong category: {probe['category']}"
            )

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        ids = [p["id"] for p in PRIVILEGE_ESCALATION_PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found in privilege escalation probes"

    def test_role_manipulation_probes(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        probes = [p for p in PRIVILEGE_ESCALATION_PROBES if p["technique"] == "role_manipulation"]
        assert len(probes) >= 5, f"Expected 5+ role manipulation probes, got {len(probes)}"

    def test_scope_expansion_probes(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        probes = [p for p in PRIVILEGE_ESCALATION_PROBES if p["technique"] == "scope_expansion"]
        assert len(probes) >= 4, f"Expected 4+ scope expansion probes, got {len(probes)}"

    def test_system_instruction_manipulation_probes(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        probes = [p for p in PRIVILEGE_ESCALATION_PROBES if p["technique"] == "system_instruction_manipulation"]
        assert len(probes) >= 4, f"Expected 4+ system instruction manipulation probes, got {len(probes)}"

    def test_context_authority_escalation_probes(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        probes = [p for p in PRIVILEGE_ESCALATION_PROBES if p["technique"] == "context_authority_escalation"]
        assert len(probes) >= 4, f"Expected 4+ context authority escalation probes, got {len(probes)}"

    def test_severity_values_valid(self):
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        valid = {"critical", "high", "medium", "low"}
        for probe in PRIVILEGE_ESCALATION_PROBES:
            assert probe["severity"] in valid, f"Probe {probe['id']} has invalid severity: {probe['severity']}"

    def test_flags_unauthorized_scope_expansion(self):
        """Acceptance: probes correctly flag unauthorized scope expansion attempts."""
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        scope_probes = [p for p in PRIVILEGE_ESCALATION_PROBES if p["technique"] == "scope_expansion"]
        assert len(scope_probes) >= 4, "Must have probes for scope expansion detection"
        for probe in scope_probes:
            payload_lower = probe["payload"].lower()
            has_escalation = any(kw in payload_lower for kw in [
                "access", "upgrade", "namespace", "scope", "permission",
                "cross-tenant", "allowlist", "model restriction", "rate limit",
            ])
            assert has_escalation, (
                f"Probe {probe['id']} should target scope expansion patterns"
            )


# ── 4. Multi-Step Attack Chain Probe Suite ──────────────────────────────────


class TestMultiStepAttackProbeSuite:
    """Validate multi-step attack chain probe suite structure and coverage."""

    def test_probe_count_minimum(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        assert len(MULTI_STEP_ATTACK_PROBES) >= 25, (
            f"Expected 25+ multi-step attack probes, got {len(MULTI_STEP_ATTACK_PROBES)}"
        )

    def test_probe_structure(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        required_keys = {"id", "name", "category", "technique", "severity", "payload", "success_indicators", "description", "owasp_mapping"}
        for probe in MULTI_STEP_ATTACK_PROBES:
            missing = required_keys - set(probe.keys())
            assert not missing, f"Probe {probe.get('id', '?')} missing keys: {missing}"

    def test_all_probes_category(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        for probe in MULTI_STEP_ATTACK_PROBES:
            assert probe["category"] == "multi_step_attack", (
                f"Probe {probe['id']} has wrong category: {probe['category']}"
            )

    def test_unique_probe_ids(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        ids = [p["id"] for p in MULTI_STEP_ATTACK_PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found in multi-step attack probes"

    def test_recon_inject_exfil_probes(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        probes = [p for p in MULTI_STEP_ATTACK_PROBES if p["technique"] == "recon_inject_exfil"]
        assert len(probes) >= 5, f"Expected 5+ recon-inject-exfil probes, got {len(probes)}"

    def test_privilege_escalation_chain_probes(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        probes = [p for p in MULTI_STEP_ATTACK_PROBES if p["technique"] == "privilege_escalation_chain"]
        assert len(probes) >= 5, f"Expected 5+ privilege escalation chain probes, got {len(probes)}"

    def test_social_engineering_chain_probes(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        probes = [p for p in MULTI_STEP_ATTACK_PROBES if p["technique"] == "social_engineering_chain"]
        assert len(probes) >= 5, f"Expected 5+ social engineering chain probes, got {len(probes)}"

    def test_persistence_evasion_probes(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        probes = [p for p in MULTI_STEP_ATTACK_PROBES if p["technique"] == "persistence_evasion"]
        assert len(probes) >= 5, f"Expected 5+ persistence/evasion probes, got {len(probes)}"

    def test_severity_values_valid(self):
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        valid = {"critical", "high", "medium", "low"}
        for probe in MULTI_STEP_ATTACK_PROBES:
            assert probe["severity"] in valid, f"Probe {probe['id']} has invalid severity: {probe['severity']}"

    def test_multi_step_payloads_contain_sequential_steps(self):
        """Verify multi-step probes actually contain multi-step attack sequences."""
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        for probe in MULTI_STEP_ATTACK_PROBES:
            payload = probe["payload"]
            step_indicators = sum(1 for marker in ["1.", "2.", "3.", "Step 1", "Step 2", "Step 3"]
                                  if marker in payload)
            assert step_indicators >= 2, (
                f"Probe {probe['id']} should contain multi-step sequences (found {step_indicators} step markers)"
            )

    def test_detects_chained_malicious_behavior(self):
        """Acceptance: probes detect chained malicious behavior spanning multiple agent turns."""
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        # Verify we have chains across different attack phases
        techniques = set(p["technique"] for p in MULTI_STEP_ATTACK_PROBES)
        assert "recon_inject_exfil" in techniques, "Must have reconnaissance-injection-exfiltration chains"
        assert "privilege_escalation_chain" in techniques, "Must have privilege escalation chains"
        assert "persistence_evasion" in techniques, "Must have persistence/evasion chains"
        # Verify all probes are multi-step
        for probe in MULTI_STEP_ATTACK_PROBES:
            assert len(probe["success_indicators"]) >= 2, (
                f"Probe {probe['id']} should have multiple success indicators for chain detection"
            )


# ── 5. Cross-Suite Validation ───────────────────────────────────────────────


class TestAgenticProbeSuiteCrossValidation:
    """Cross-suite validation for all Sprint 24A agentic probes."""

    def test_no_duplicate_ids_across_suites(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        all_ids = (
            [p["id"] for p in TOOL_CALL_INJECTION_PROBES]
            + [p["id"] for p in MEMORY_POISONING_PROBES]
            + [p["id"] for p in PRIVILEGE_ESCALATION_PROBES]
            + [p["id"] for p in MULTI_STEP_ATTACK_PROBES]
        )
        assert len(all_ids) == len(set(all_ids)), "Duplicate probe IDs found across Sprint 24A suites"

    def test_total_agentic_probe_count(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        total = (
            len(TOOL_CALL_INJECTION_PROBES)
            + len(MEMORY_POISONING_PROBES)
            + len(PRIVILEGE_ESCALATION_PROBES)
            + len(MULTI_STEP_ATTACK_PROBES)
        )
        assert total >= 100, f"Expected 100+ total agentic probes, got {total}"

    def test_all_suites_have_owasp_mapping(self):
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        all_probes = (
            TOOL_CALL_INJECTION_PROBES + MEMORY_POISONING_PROBES
            + PRIVILEGE_ESCALATION_PROBES + MULTI_STEP_ATTACK_PROBES
        )
        for probe in all_probes:
            assert probe["owasp_mapping"], f"Probe {probe['id']} missing OWASP mapping"
            assert probe["owasp_mapping"].startswith("LLM"), (
                f"Probe {probe['id']} has invalid OWASP mapping: {probe['owasp_mapping']}"
            )

    def test_id_prefix_conventions(self):
        """Verify each suite uses its own ID prefix."""
        from app.services.red_team.probes.tool_call_injection import TOOL_CALL_INJECTION_PROBES
        from app.services.red_team.probes.memory_poisoning import MEMORY_POISONING_PROBES
        from app.services.red_team.probes.privilege_escalation import PRIVILEGE_ESCALATION_PROBES
        from app.services.red_team.probes.multi_step_attack import MULTI_STEP_ATTACK_PROBES
        for probe in TOOL_CALL_INJECTION_PROBES:
            assert probe["id"].startswith("TCI-"), f"Tool call injection probe {probe['id']} should start with TCI-"
        for probe in MEMORY_POISONING_PROBES:
            assert probe["id"].startswith("MEM-"), f"Memory poisoning probe {probe['id']} should start with MEM-"
        for probe in PRIVILEGE_ESCALATION_PROBES:
            assert probe["id"].startswith("PRIV-"), f"Privilege escalation probe {probe['id']} should start with PRIV-"
        for probe in MULTI_STEP_ATTACK_PROBES:
            assert probe["id"].startswith("MSA-"), f"Multi-step attack probe {probe['id']} should start with MSA-"


# ── 6. Runner Integration ──────────────────────────────────────────────────


class TestRunnerIntegration:
    """Validate runner correctly integrates Sprint 24A probe categories."""

    def test_runner_includes_new_categories(self):
        from app.services.red_team.runner import _get_all_probes
        all_probes = _get_all_probes()
        assert "tool_call_injection" in all_probes, "Runner missing tool_call_injection category"
        assert "memory_poisoning" in all_probes, "Runner missing memory_poisoning category"
        assert "privilege_escalation" in all_probes, "Runner missing privilege_escalation category"
        assert "multi_step_attack" in all_probes, "Runner missing multi_step_attack category"

    def test_campaign_default_categories_include_new(self):
        from app.services.red_team.runner import Campaign
        campaign = Campaign(name="test", target_url="http://localhost")
        assert "tool_call_injection" in campaign.probe_categories
        assert "memory_poisoning" in campaign.probe_categories
        assert "privilege_escalation" in campaign.probe_categories
        assert "multi_step_attack" in campaign.probe_categories

    def test_campaign_selective_category(self):
        from app.services.red_team.runner import Campaign
        campaign = Campaign(
            name="agentic-only",
            target_url="http://localhost",
            probe_categories=["tool_call_injection", "memory_poisoning"],
        )
        assert campaign.probe_categories == ["tool_call_injection", "memory_poisoning"]

    def test_recommendations_for_new_categories(self):
        """Verify runner generates recommendations for Sprint 24A categories."""
        from app.services.red_team.runner import Campaign, ProbeResult, ProbeSeverity
        campaign = Campaign(name="test", target_url="http://localhost")
        # Add fake detected results for each new category
        for cat in ["tool_call_injection", "memory_poisoning", "privilege_escalation", "multi_step_attack"]:
            campaign.results.append(ProbeResult(
                probe_id=f"TEST-{cat}",
                probe_name=f"Test {cat}",
                category=cat,
                technique="test",
                severity=ProbeSeverity.CRITICAL,
                detected=True,
                risk_score=1.0,
            ))
        recs = campaign._generate_recommendations()
        rec_categories = [r["category"] for r in recs]
        assert "tool_call_injection" in rec_categories, "Missing recommendation for tool_call_injection"
        assert "memory_poisoning" in rec_categories, "Missing recommendation for memory_poisoning"
        assert "privilege_escalation" in rec_categories, "Missing recommendation for privilege_escalation"
        assert "multi_step_attack" in rec_categories, "Missing recommendation for multi_step_attack"

    def test_total_probe_count_with_all_suites(self):
        from app.services.red_team.runner import _get_all_probes
        all_probes = _get_all_probes()
        total = sum(len(probes) for probes in all_probes.values())
        # Sprint 23: 100+ injection + 50+ jailbreak + 30+ PII = 180+
        # Sprint 24A: 30 TCI + 30 MEM + 25 PRIV + 30 MSA = 115
        # Total: 295+
        assert total >= 290, f"Expected 290+ total probes across all suites, got {total}"
