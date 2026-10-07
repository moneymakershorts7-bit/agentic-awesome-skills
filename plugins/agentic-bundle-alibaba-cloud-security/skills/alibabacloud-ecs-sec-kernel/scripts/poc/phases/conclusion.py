"""
ConclusionEngine - Final Conclusion Calculator

Calculates the final precise conclusion based on three-phase verification results.
"""
import logging
from typing import Optional

from ...core.result import (
    PoCResult, PoCStatus, PrepareResult, PostResult
)

logger = logging.getLogger(__name__)


class ConclusionEngine:
    """
    Conclusion Engine

    Calculates the final precise conclusion based on:
    - Run phase status (EXPLOITABLE/NOT_EXPLOITABLE as nobody)
    - Prepare phase success
    - Post phase verification

    Core principle: Local Privilege Escalation (LPE) vulnerabilities
    are only meaningful if a regular user can trigger them.
    """

    def calculate(self, run_status: str,
                  prepare_result: Optional[PrepareResult] = None,
                  post_result: Optional[PostResult] = None) -> dict:
        """
        Calculate final conclusion.

        Args:
            run_status: Run phase PoC status string
            prepare_result: Prepare phase result (optional)
            post_result: Post phase result (optional)

        Returns:
            Dict with final_conclusion and confidence
        """
        conclusion, confidence = self._calculate_from_run_status(run_status)

        # Adjust confidence based on preparation and verification
        if prepare_result and not prepare_result.success:
            # Prepare failed - lower confidence
            confidence = max(0.0, confidence - 0.2)
            logger.warning(
                "Prepare phase failed, reducing confidence to %.2f",
                confidence
            )

        if post_result:
            # Warnings are reported separately in Post result
            # No need to modify the conclusion string
            pass

        return {
            "final_conclusion": conclusion,
            "confidence": confidence,
        }

    def _calculate_from_run_status(self, run_status: str) -> tuple:
        """
        Calculate conclusion from Run phase status.

        Run phase executes as nobody (unprivileged user).
        The conclusion directly reflects the security threat.

        Returns:
            Tuple of (conclusion_string, confidence)
        """
        if run_status == "EXPLOITABLE":
            # Regular user can trigger vulnerability = USER_EXPLOITABLE
            # After three-phase verification confirms exploitability,
            # the final conclusion is upgraded to USER_EXPLOITABLE
            return PoCStatus.USER_EXPLOITABLE.value, 0.98
        elif run_status == "NOT_EXPLOITABLE":
            # Regular user cannot trigger = NOT_EXPLOITABLE
            return PoCStatus.NOT_EXPLOITABLE.value, 0.90
        elif run_status == "ERROR":
            return PoCStatus.POC_ERROR.value, 0.0
        elif run_status == "NO_POC":
            return PoCStatus.NO_POC.value, 0.0
        else:
            # Unknown status - default to NOT_EXPLOITABLE
            return PoCStatus.NOT_EXPLOITABLE.value, 0.5

    def format_summary(self, result: PoCResult) -> str:
        """
        Format a human-readable summary of the PoC verification.

        Args:
            result: Complete PoCResult with all phases

        Returns:
            Human-readable summary string
        """
        lines = [
            f"PoC Verification Summary for {result.final_conclusion or 'N/A'}",
            f"  Run Phase Status: {result.status} (as user: {result.user})",
            f"  Final Conclusion: {result.final_conclusion}",
            f"  Confidence: {result.confidence:.2f}",
        ]

        if result.prepare:
            prep = result.prepare
            lines.append(
                f"  Prepare Phase: {'Success' if prep.success else 'Failed'} "
                f"({len(prep.operations)} operations, {prep.duration:.2f}s)"
            )

        if result.post:
            post = result.post
            lines.append(
                f"  Post Phase: {'Success' if post.success else 'Warnings'} "
                f"(self_check: {'clean' if post.self_check.clean else 'issues'}, "
                f"global_verify: {'restored' if post.global_verify.system_restored else 'not_restored'}, "
                f"{post.duration:.2f}s)"
            )

            # Add warnings
            warnings = []
            if post.self_check.issues:
                warnings.extend(post.self_check.issues)
            if post.global_verify.warnings:
                warnings.extend(post.global_verify.warnings)
            if post.global_verify.kernel_messages:
                warnings.extend(post.global_verify.kernel_messages)

            if warnings:
                lines.append("  Warnings:")
                for w in warnings[:5]:  # Limit to first 5 warnings
                    lines.append(f"    - {w}")
                if len(warnings) > 5:
                    lines.append(f"    ... and {len(warnings) - 5} more")

        return "\n".join(lines)
