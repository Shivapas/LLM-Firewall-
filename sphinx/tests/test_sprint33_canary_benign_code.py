"""SP-334 Benign Sub-task 2: Code Generation Sessions (10 benign sessions).

Validates that 10 code generation sessions produce ZERO false positives.
Code responses may contain HTML comments, XML tags, and special characters
that could resemble canary patterns but should NOT trigger detection.

Session topics:
  1. Python function
  2. JavaScript async/await
  3. HTML page with comments
  4. SQL query
  5. React component
  6. Bash script
  7. Go HTTP handler
  8. CSS stylesheet
  9. Rust struct
 10. YAML configuration
"""

import pytest

from app.services.canary.generator import CanaryTokenGenerator, reset_canary_generator
from app.services.canary.injector import CanaryInjector, reset_canary_injector
from app.services.canary.scanner import CanaryOutputScanner, reset_canary_scanner


@pytest.fixture
def generator():
    reset_canary_generator()
    gen = CanaryTokenGenerator(secret_key="test-benign-code-key", default_ttl_seconds=600.0)
    yield gen
    reset_canary_generator()


@pytest.fixture
def injector(generator):
    reset_canary_injector()
    inj = CanaryInjector(generator=generator, enabled=True)
    yield inj
    reset_canary_injector()


@pytest.fixture
def scanner(generator):
    reset_canary_scanner()
    sc = CanaryOutputScanner(generator=generator)
    yield sc
    reset_canary_scanner()


def _setup_session(injector, session_id):
    _, canary = injector.inject("You are a code assistant.", session_id)
    return canary.token


class TestBenignCodeSessions:
    """10 code generation sessions — 0 false positives expected."""

    def test_benign_code_01_python(self, injector, scanner):
        """Session 1: Python function."""
        sid = "benign-code-01"
        _setup_session(injector, sid)
        response = (
            "Here's a Python function to calculate Fibonacci numbers:\n\n"
            "```python\n"
            "def fibonacci(n: int) -> int:\n"
            "    if n <= 1:\n"
            "        return n\n"
            "    a, b = 0, 1\n"
            "    for _ in range(2, n + 1):\n"
            "        a, b = b, a + b\n"
            "    return b\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on Python code generation"

    def test_benign_code_02_javascript(self, injector, scanner):
        """Session 2: JavaScript async/await."""
        sid = "benign-code-02"
        _setup_session(injector, sid)
        response = (
            "Here's an async function to fetch data:\n\n"
            "```javascript\n"
            "async function fetchData(url) {\n"
            "  try {\n"
            "    const response = await fetch(url);\n"
            "    const data = await response.json();\n"
            "    return data;\n"
            "  } catch (error) {\n"
            "    console.error('Failed to fetch:', error);\n"
            "    throw error;\n"
            "  }\n"
            "}\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on JavaScript code generation"

    def test_benign_code_03_html_with_comments(self, injector, scanner):
        """Session 3: HTML page with comments (could resemble canary format)."""
        sid = "benign-code-03"
        _setup_session(injector, sid)
        response = (
            "Here's a basic HTML page:\n\n"
            "```html\n"
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "  <!-- Main stylesheet -->\n"
            "  <link rel='stylesheet' href='styles.css'>\n"
            "  <!-- Page metadata -->\n"
            "  <meta charset='UTF-8'>\n"
            "  <title>My Page</title>\n"
            "</head>\n"
            "<body>\n"
            "  <!-- Navigation section -->\n"
            "  <nav>Menu</nav>\n"
            "  <!-- Content area -->\n"
            "  <main>Hello World</main>\n"
            "</body>\n"
            "</html>\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on HTML with comments"

    def test_benign_code_04_sql(self, injector, scanner):
        """Session 4: SQL query."""
        sid = "benign-code-04"
        _setup_session(injector, sid)
        response = (
            "Here's a SQL query to find top customers:\n\n"
            "```sql\n"
            "SELECT c.customer_name, SUM(o.total_amount) AS total_spent\n"
            "FROM customers c\n"
            "JOIN orders o ON c.id = o.customer_id\n"
            "WHERE o.order_date >= '2024-01-01'\n"
            "GROUP BY c.customer_name\n"
            "HAVING SUM(o.total_amount) > 1000\n"
            "ORDER BY total_spent DESC\n"
            "LIMIT 10;\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on SQL code generation"

    def test_benign_code_05_react(self, injector, scanner):
        """Session 5: React component."""
        sid = "benign-code-05"
        _setup_session(injector, sid)
        response = (
            "Here's a React component:\n\n"
            "```jsx\n"
            "import React, { useState } from 'react';\n\n"
            "function Counter() {\n"
            "  const [count, setCount] = useState(0);\n"
            "  return (\n"
            "    <div className='counter'>\n"
            "      <h2>Count: {count}</h2>\n"
            "      <button onClick={() => setCount(count + 1)}>+</button>\n"
            "      <button onClick={() => setCount(count - 1)}>-</button>\n"
            "    </div>\n"
            "  );\n"
            "}\n\n"
            "export default Counter;\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on React component"

    def test_benign_code_06_bash(self, injector, scanner):
        """Session 6: Bash script."""
        sid = "benign-code-06"
        _setup_session(injector, sid)
        response = (
            "Here's a bash script for deployment:\n\n"
            "```bash\n"
            "#!/bin/bash\n"
            "set -euo pipefail\n\n"
            "# Configuration\n"
            "APP_NAME=\"myapp\"\n"
            "DEPLOY_DIR=\"/opt/${APP_NAME}\"\n\n"
            "echo \"Deploying ${APP_NAME}...\"\n"
            "docker build -t ${APP_NAME}:latest .\n"
            "docker stop ${APP_NAME} || true\n"
            "docker run -d --name ${APP_NAME} -p 8080:8080 ${APP_NAME}:latest\n"
            "echo \"Deployment complete!\"\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on bash script"

    def test_benign_code_07_go(self, injector, scanner):
        """Session 7: Go HTTP handler."""
        sid = "benign-code-07"
        _setup_session(injector, sid)
        response = (
            "Here's a Go HTTP handler:\n\n"
            "```go\n"
            "package main\n\n"
            "import (\n"
            '    "encoding/json"\n'
            '    "net/http"\n'
            ")\n\n"
            "type Response struct {\n"
            '    Message string `json:"message"`\n'
            '    Status  int    `json:"status"`\n'
            "}\n\n"
            "func healthHandler(w http.ResponseWriter, r *http.Request) {\n"
            '    resp := Response{Message: "ok", Status: 200}\n'
            '    w.Header().Set("Content-Type", "application/json")\n'
            "    json.NewEncoder(w).Encode(resp)\n"
            "}\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on Go HTTP handler"

    def test_benign_code_08_css(self, injector, scanner):
        """Session 8: CSS stylesheet."""
        sid = "benign-code-08"
        _setup_session(injector, sid)
        response = (
            "Here's a CSS stylesheet:\n\n"
            "```css\n"
            "/* Reset styles */\n"
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n\n"
            "/* Main layout */\n"
            ".container {\n"
            "  max-width: 1200px;\n"
            "  margin: 0 auto;\n"
            "  padding: 20px;\n"
            "}\n\n"
            "/* Typography */\n"
            "h1 { font-size: 2.5rem; color: #333; }\n"
            "p { line-height: 1.6; color: #666; }\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on CSS stylesheet"

    def test_benign_code_09_rust(self, injector, scanner):
        """Session 9: Rust struct."""
        sid = "benign-code-09"
        _setup_session(injector, sid)
        response = (
            "Here's a Rust struct with implementation:\n\n"
            "```rust\n"
            "#[derive(Debug, Clone)]\n"
            "struct Point {\n"
            "    x: f64,\n"
            "    y: f64,\n"
            "}\n\n"
            "impl Point {\n"
            "    fn new(x: f64, y: f64) -> Self {\n"
            "        Point { x, y }\n"
            "    }\n\n"
            "    fn distance(&self, other: &Point) -> f64 {\n"
            "        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2)).sqrt()\n"
            "    }\n"
            "}\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on Rust struct"

    def test_benign_code_10_yaml(self, injector, scanner):
        """Session 10: YAML configuration."""
        sid = "benign-code-10"
        _setup_session(injector, sid)
        response = (
            "Here's a YAML configuration for a Kubernetes deployment:\n\n"
            "```yaml\n"
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: myapp\n"
            "  labels:\n"
            "    app: myapp\n"
            "spec:\n"
            "  replicas: 3\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app: myapp\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: myapp\n"
            "        image: myapp:latest\n"
            "        ports:\n"
            "        - containerPort: 8080\n"
            "```"
        )
        result = scanner.scan_response(response, sid, turn_index=0)
        assert not result.detected, "False positive on YAML configuration"


class TestBenignCodeAggregate:
    """Aggregate: 0 false positives across all 10 code sessions."""

    def test_zero_false_positives_code_sessions(self, injector, scanner):
        """0/10 code sessions produce false positives."""
        code_responses = [
            ("code-agg-01", "def fibonacci(n): return n if n <= 1 else fibonacci(n-1) + fibonacci(n-2)"),
            ("code-agg-02", "const data = await fetch('/api/data').then(r => r.json());"),
            ("code-agg-03", "<!-- Navigation --> <nav>Menu</nav> <!-- Content --> <main>Hello</main>"),
            ("code-agg-04", "SELECT * FROM users WHERE created_at > '2024-01-01' ORDER BY id DESC;"),
            ("code-agg-05", "const [count, setCount] = useState(0); return <div>{count}</div>;"),
            ("code-agg-06", "#!/bin/bash\necho 'deploying...'\ndocker build -t app ."),
            ("code-agg-07", 'func main() { http.HandleFunc("/", handler); http.ListenAndServe(":8080", nil) }'),
            ("code-agg-08", ".container { max-width: 1200px; margin: 0 auto; }"),
            ("code-agg-09", "struct Point { x: f64, y: f64 } impl Point { fn new(x: f64, y: f64) -> Self { Point { x, y } } }"),
            ("code-agg-10", "apiVersion: v1\nkind: Service\nmetadata:\n  name: myapp"),
        ]
        false_positives = 0
        for sid, resp in code_responses:
            _setup_session(injector, sid)
            result = scanner.scan_response(resp, sid, turn_index=0)
            if result.detected:
                false_positives += 1

        assert false_positives == 0, f"Code sessions: {false_positives} false positives (expected 0)"
