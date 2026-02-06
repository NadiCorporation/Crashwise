#!/usr/bin/env python3
# Copyright (c) 2026 Crashwise
#
# Licensed under the MIT License. See the LICENSE file for details.

"""
Quick demo to save findings to a SARIF file.
"""

from pathlib import Path
from crashwise_sdk import CrashwiseClient
from crashwise_sdk.utils import create_workflow_submission, save_sarif_to_file, format_sarif_summary

def main():
    """Save findings demo."""
    client = CrashwiseClient(base_url="http://localhost:8000")

    try:
        # List workflows
        workflows = client.list_workflows()
        if not workflows:
            print("❌ No workflows available")
            return

        # Submit workflow
        workflow_name = workflows[0].name
        submission = create_workflow_submission(
            target_path=Path.cwd().absolute(),
            timeout=300
        )

        print(f"🚀 Submitting {workflow_name}...")
        response = client.submit_workflow(workflow_name, submission)

        # Wait for completion
        print("⏱️  Waiting for completion...")
        final_status = client.wait_for_completion(response.run_id)

        if final_status.is_completed:
            # Get findings
            findings = client.get_run_findings(response.run_id)
            summary = format_sarif_summary(findings.sarif)
            print(f"📈 {summary}")

            # Save to file
            output_file = Path("crashwise_findings.sarif.json")
            save_sarif_to_file(findings.sarif, output_file)
            print(f"💾 Findings saved to: {output_file.absolute()}")

            # Show file info
            print(f"📄 File size: {output_file.stat().st_size:,} bytes")

        else:
            print(f"❌ Workflow failed: {final_status.status}")

    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main()