#!/usr/bin/env python3
"""
OpenID Conformance Suite Test Runner for xavyo-idp

Usage:
    python run-tests.py --plan oidcc-basic-certification-test-plan
    python run-tests.py --plan oidcc-basic-certification-test-plan --output results.json
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
import ssl

# Disable SSL verification for local testing
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


class ConformanceSuiteAPI:
    """Simple API client for OpenID Conformance Suite."""

    def __init__(self, base_url: str = "https://www.certification.openid.net"):
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, data: dict = None) -> dict:
        """Make HTTP request to conformance suite."""
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=ssl_context, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            print(f"HTTP Error {e.code}: {e.read().decode()}")
            raise

    def create_plan(self, plan_name: str, config: dict) -> str:
        """Create a new test plan."""
        result = self._request("POST", "/api/plan", {
            "planName": plan_name,
            **config
        })
        return result.get("id")

    def get_plan(self, plan_id: str) -> dict:
        """Get test plan status."""
        return self._request("GET", f"/api/plan/{plan_id}")

    def start_test(self, plan_id: str, test_name: str) -> str:
        """Start a specific test in the plan."""
        result = self._request("POST", f"/api/runner/{plan_id}", {
            "test": test_name
        })
        return result.get("id")

    def get_test_status(self, test_id: str) -> dict:
        """Get test execution status."""
        return self._request("GET", f"/api/info/{test_id}")

    def get_test_log(self, test_id: str) -> list:
        """Get test execution log."""
        return self._request("GET", f"/api/log/{test_id}")


def get_default_config() -> dict:
    """Get default test configuration from environment."""
    return {
        "alias": os.environ.get("OIDC_TEST_ALIAS", "xavyo-idp"),
        "description": "xavyo-idp OIDC Conformance Test",
        "server": {
            "discoveryUrl": os.environ.get(
                "OIDC_DISCOVERY_URL",
                "http://host.docker.internal:8080/.well-known/openid-configuration"
            )
        },
        "client": {
            "client_id": os.environ.get("OIDC_TEST_CLIENT_ID", "conformance-test-client-1"),
            "client_secret": os.environ.get("OIDC_TEST_CLIENT_SECRET", "conformance-test-secret-1")
        },
        "client2": {
            "client_id": os.environ.get("OIDC_TEST_CLIENT2_ID", "conformance-test-client-2"),
            "client_secret": os.environ.get("OIDC_TEST_CLIENT2_SECRET", "conformance-test-secret-2")
        },
        "variant": {
            "client_auth_type": "client_secret_basic",
            "response_type": "code",
            "response_mode": "default",
            "client_registration": "static_client"
        }
    }


def run_conformance_tests(
    plan_name: str,
    base_url: str = "https://localhost:8443",
    config: dict = None
) -> dict:
    """Run conformance tests and return results."""
    api = ConformanceSuiteAPI(base_url)
    config = config or get_default_config()

    print(f"Creating test plan: {plan_name}")
    plan_id = api.create_plan(plan_name, config)
    print(f"Test plan created: {plan_id}")

    # Get plan details
    plan = api.get_plan(plan_id)
    tests = plan.get("modules", [])

    results = {
        "plan_id": plan_id,
        "plan_name": plan_name,
        "tests": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "skipped": 0
    }

    for test in tests:
        test_name = test.get("testModule")
        print(f"\nRunning test: {test_name}")

        try:
            test_id = api.start_test(plan_id, test_name)

            # Wait for test completion
            for _ in range(60):  # Max 60 seconds per test
                status = api.get_test_status(test_id)
                state = status.get("status")

                if state in ("FINISHED", "INTERRUPTED"):
                    break
                time.sleep(1)

            result = status.get("result", "UNKNOWN")
            print(f"  Result: {result}")

            results["tests"].append({
                "name": test_name,
                "id": test_id,
                "result": result
            })

            if result == "PASSED":
                results["passed"] += 1
            elif result == "FAILED":
                results["failed"] += 1
            elif result == "WARNING":
                results["warnings"] += 1
            else:
                results["skipped"] += 1

        except Exception as e:
            print(f"  Error: {e}")
            results["tests"].append({
                "name": test_name,
                "error": str(e)
            })
            results["failed"] += 1

    # Summary
    total = results["passed"] + results["failed"] + results["warnings"] + results["skipped"]
    print(f"\n{'='*50}")
    print(f"CONFORMANCE TEST RESULTS")
    print(f"{'='*50}")
    print(f"Total:    {total}")
    print(f"Passed:   {results['passed']}")
    print(f"Failed:   {results['failed']}")
    print(f"Warnings: {results['warnings']}")
    print(f"Skipped:  {results['skipped']}")
    print(f"{'='*50}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Run OIDC Conformance Tests")
    parser.add_argument(
        "--plan",
        default="oidcc-basic-certification-test-plan",
        help="Test plan name (default: oidcc-basic-certification-test-plan)"
    )
    parser.add_argument(
        "--url",
        default="https://localhost:8443",
        help="Conformance suite URL (default: https://localhost:8443)"
    )
    parser.add_argument(
        "--output",
        help="Output file for results (JSON)"
    )
    parser.add_argument(
        "--config",
        help="Config file (JSON)"
    )

    args = parser.parse_args()

    # Load config from file if provided
    config = None
    if args.config:
        with open(args.config) as f:
            config = json.load(f)

    # Run tests
    try:
        results = run_conformance_tests(args.plan, args.url, config)
    except Exception as e:
        print(f"Error running tests: {e}")
        sys.exit(1)

    # Save results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    # Exit with error code if tests failed
    if results["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
