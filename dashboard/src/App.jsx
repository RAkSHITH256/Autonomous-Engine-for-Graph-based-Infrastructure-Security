import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";
import "./App.css";

const API_URL =
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  // ============================================================
  // LOAD DATA FROM AEGIS BACKEND
  // ============================================================

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_URL}/dashboard`, {
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const result = await response.json();

      console.log("AEGIS dashboard data:", result);

      setData(result);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Dashboard API error:", err);
      setError(err.message || "Unable to connect to backend");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  // ============================================================
  // BACKEND DATA
  // ============================================================

  const summary = data?.summary ?? {};

  const findings = Array.isArray(data?.findings)
    ? data.findings
    : [];

  const attackPath = data?.attack_path ?? {};

  const pathNodes = Array.isArray(attackPath.nodes)
    ? attackPath.nodes
    : [];

  const finding = findings[0] ?? null;

  // ============================================================
  // GRAPH
  // ============================================================

  const graph = useMemo(() => {
    if (!pathNodes.length) {
      return {
        nodes: [],
        edges: [],
      };
    }

    const nodes = pathNodes.map((node, index) => {
      const criticality =
        String(node.criticality || "").toUpperCase();

      return {
        id: String(
          node.asset_id ??
          node.id ??
          `node-${index}`
        ),

        position: {
          x: index * 250,
          y: 100,
        },

        data: {
          label: (
            <div
              className={`graph-node ${criticality === "CRITICAL"
                  ? "graph-critical"
                  : ""
                }`}
            >
              <div className="graph-node-icon">
                {getNodeIcon(node.type)}
              </div>

              <div className="graph-node-type">
                {node.type || "ASSET"}
              </div>

              <div className="graph-node-name">
                {node.name ||
                  node.asset_id ||
                  node.id ||
                  "Unknown"}
              </div>

              {node.criticality && (
                <div className="graph-node-criticality">
                  {node.criticality}
                </div>
              )}
            </div>
          ),
        },

        style: {
          background: "transparent",
          border: "none",
          padding: 0,
          width: 190,
        },
      };
    });

    const edges = [];

    for (let i = 0; i < pathNodes.length - 1; i++) {
      const source =
        pathNodes[i].asset_id ??
        pathNodes[i].id ??
        `node-${i}`;

      const target =
        pathNodes[i + 1].asset_id ??
        pathNodes[i + 1].id ??
        `node-${i + 1}`;

      const targetCriticality =
        String(
          pathNodes[i + 1].criticality || ""
        ).toUpperCase();

      edges.push({
        id: `${source}-${target}`,

        source: String(source),

        target: String(target),

        animated: true,

        style: {
          stroke:
            targetCriticality === "CRITICAL"
              ? "#ff5364"
              : "#64748b",

          strokeWidth: 2,
        },
      });
    }

    return {
      nodes,
      edges,
    };
  }, [pathNodes]);

  // ============================================================
  // DYNAMIC RISK FACTORS
  // ============================================================

  /*
   * IMPORTANT:
   *
   * The frontend no longer invents risk scores.
   *
   * If backend returns:
   *
   * risk: {
   *   factors: [...]
   * }
   *
   * those factors are displayed directly.
   *
   * Otherwise, we only display information that actually
   * exists in the finding.
   */

  const riskFactors = useMemo(() => {
    const backendFactors =
      data?.risk?.factors ??
      data?.risk_factors ??
      finding?.risk?.factors;

    if (Array.isArray(backendFactors)) {
      return backendFactors.map((factor, index) => ({
        name:
          factor.name ??
          factor.label ??
          `Factor ${index + 1}`,

        value:
          factor.value ??
          factor.score ??
          0,

        description:
          factor.description ??
          "",
      }));
    }

    return [];
  }, [data, finding]);

  const maxRiskFactor = Math.max(
    ...riskFactors.map(
      (factor) => Number(factor.value) || 0
    ),
    1
  );

  // ============================================================
  // LOADING
  // ============================================================

  if (loading && !data) {
    return (
      <div className="loading-screen">
        <div className="loading-logo">
          AEGIS
        </div>

        <div className="loading-line" />

        <p>
          Loading security intelligence...
        </p>
      </div>
    );
  }

  // ============================================================
  // ERROR
  // ============================================================

  if (error && !data) {
    return (
      <div className="app">
        <header className="header">
          <div className="brand">
            <div className="brand-mark">
              A
            </div>

            <div>
              <h1>AEGIS</h1>

              <p>
                Autonomous Engine for Graph-based
                Infrastructure Security
              </p>
            </div>
          </div>
        </header>

        <main>
          <div className="error">
            <div className="error-icon">
              !
            </div>

            <div>
              <h2>
                Backend connection failed
              </h2>

              <p>{error}</p>

              <p className="muted">
                Make sure FastAPI is running on{" "}
                <code>{API_URL}</code>
              </p>

              <button
                className="primary-button"
                onClick={loadDashboard}
              >
                Retry connection
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // ============================================================
  // DYNAMIC VALUES
  // ============================================================

  const riskScore = Number(
    summary.overall_risk ??
    summary.risk_score ??
    data?.risk?.score ??
    0
  );

  const riskLevel =
    summary.risk_level ??
    data?.risk?.level ??
    "UNKNOWN";

  const findingCount =
    summary.finding_count ??
    summary.findings ??
    findings.length;

  const pathLength =
    attackPath.path_length ??
    Math.max(pathNodes.length - 1, 0);

  const priority =
    finding?.priority ??
    data?.decision?.priority ??
    "—";

  const decision =
    finding?.decision ??
    data?.decision?.decision ??
    "No decision";

  const remediation =
    finding?.remediation ??
    data?.decision?.remediation ??
    "No remediation recommendation available.";

  // ============================================================
  // MAIN
  // ============================================================

  return (
    <div className="app">

      {/* HEADER */}

      <header className="header">

        <div className="brand">

          <div className="brand-mark">
            A
          </div>

          <div>
            <h1>AEGIS</h1>

            <p>
              Autonomous Engine for Graph-based
              Infrastructure Security
            </p>
          </div>

        </div>

        <div className="header-actions">

          <div className="connection-status">
            <span className="status-dot" />
            SYSTEM ONLINE
          </div>

          <button
            className="refresh-button"
            onClick={loadDashboard}
            disabled={loading}
            title="Refresh security analysis"
          >
            {loading ? "…" : "↻"}
          </button>

        </div>

      </header>

      <main>

        {/* HERO */}

        <section className="hero">

          <div>

            <div className="eyebrow">
              SECURITY OPERATIONS CENTER
            </div>

            <h2>
              Infrastructure Security Overview
            </h2>

            <p>
              Real-time graph-based analysis of
              vulnerabilities, attack paths and
              remediation decisions.
            </p>

          </div>

          <div className="updated">

            <span>LAST ANALYSIS</span>

            <strong>
              {lastUpdated
                ? lastUpdated.toLocaleTimeString()
                : "—"}
            </strong>

          </div>

        </section>

        {/* OVERVIEW */}

        <section className="overview">

          {/* RISK */}

          <div className="risk-card card">

            <div className="card-top">

              <span className="label">
                OVERALL RISK
              </span>

              <span
                className={`status-pill ${getRiskClass(
                  riskLevel
                )}`}
              >
                {riskLevel}
              </span>

            </div>

            <div className="risk-display">

              <span className="risk-number">
                {riskScore}
              </span>

              <span className="risk-max">
                /100
              </span>

            </div>

            <div className="risk-meter">

              <div
                className="risk-meter-fill"
                style={{
                  width: `${Math.min(
                    Math.max(riskScore, 0),
                    100
                  )}%`,
                }}
              />

            </div>

            <p className="risk-caption">
              {summary.risk_description ??
                data?.risk?.description ??
                "Risk assessment generated by AEGIS."}
            </p>

          </div>

          {/* FINDINGS */}

          <div className="metric-card card">

            <span className="label">
              FINDINGS
            </span>

            <div className="metric">
              {findingCount}
            </div>

            <span className="metric-description">
              Vulnerabilities detected
            </span>

          </div>

          {/* ATTACK PATH */}

          <div className="metric-card card">

            <span className="label">
              ATTACK PATH
            </span>

            <div className="metric">
              {pathLength}
            </div>

            <span className="metric-description">
              Relationships traversed
            </span>

          </div>

          {/* PRIORITY */}

          <div className="metric-card card">

            <span className="label">
              PRIORITY
            </span>

            <div className="metric priority-value">
              {priority}
            </div>

            <span className="metric-description">
              Remediation priority
            </span>

          </div>

        </section>

        {/* ATTACK GRAPH */}

        <section className="panel graph-panel">

          <div className="panel-header">

            <div>

              <div className="section-kicker">
                GRAPH ANALYSIS
              </div>

              <h2>
                Attack Path
              </h2>

              <p>
                {attackPath.description ??
                  "Attack path generated from the AEGIS graph engine."}
              </p>

            </div>

            <div className="graph-legend">

              <span>
                <i className="legend-dot normal" />
                Asset
              </span>

              <span>
                <i className="legend-dot danger" />
                Critical
              </span>

            </div>

          </div>

          <div className="graph-container">

            {graph.nodes.length > 0 ? (

              <ReactFlow
                nodes={graph.nodes}
                edges={graph.edges}

                onNodeClick={(_, node) => {

                  const selected =
                    pathNodes.find(
                      (item) =>
                        String(
                          item.asset_id ??
                          item.id
                        ) === node.id
                    );

                  setSelectedNode(
                    selected || null
                  );
                }}

                fitView

                fitViewOptions={{
                  padding: 0.2,
                }}

                attributionPosition="bottom-left"
              >

                <Background
                  gap={24}
                  size={1}
                  color="#202b36"
                />

                <Controls />

                <MiniMap
                  nodeColor={(node) => {

                    const asset =
                      pathNodes.find(
                        (item) =>
                          String(
                            item.asset_id ??
                            item.id
                          ) === node.id
                      );

                    return String(
                      asset?.criticality || ""
                    ).toUpperCase() ===
                      "CRITICAL"
                      ? "#ff5364"
                      : "#64748b";
                  }}
                />

              </ReactFlow>

            ) : (

              <div className="empty-state">
                No attack path available.
              </div>

            )}

          </div>

        </section>

        {/* SELECTED NODE */}

        {selectedNode && (

          <section className="panel selected-node-panel">

            <div className="panel-header">

              <div>

                <div className="section-kicker">
                  ASSET INSPECTION
                </div>

                <h2>
                  {selectedNode.name ??
                    selectedNode.asset_id ??
                    "Unknown Asset"}
                </h2>

                <p>
                  Infrastructure node details
                </p>

              </div>

              <button
                className="close-button"
                onClick={() =>
                  setSelectedNode(null)
                }
              >
                ×
              </button>

            </div>

            <div className="selected-node-grid">

              {Object.entries(selectedNode)
                .filter(
                  ([key]) =>
                    ![
                      "metadata",
                      "properties",
                    ].includes(key)
                )
                .map(([key, value]) => (

                  <div
                    className="detail-box"
                    key={key}
                  >

                    <span className="label">
                      {formatLabel(key)}
                    </span>

                    <strong>
                      {formatValue(value)}
                    </strong>

                  </div>

                ))}

            </div>

          </section>

        )}

        {/* RISK ANALYSIS */}

        {finding && (

          <section className="two-column">

            {/* RISK FACTORS */}

            <div className="panel">

              <div className="panel-header">

                <div>

                  <div className="section-kicker">
                    RISK ENGINE
                  </div>

                  <h2>
                    Risk Factors
                  </h2>

                </div>

                <span
                  className={`status-pill ${getRiskClass(
                    riskLevel
                  )}`}
                >
                  SCORE {riskScore}
                </span>

              </div>

              <div className="risk-factors">

                {riskFactors.length > 0 ? (

                  riskFactors.map(
                    (factor, index) => {

                      const value =
                        Number(
                          factor.value
                        ) || 0;

                      return (

                        <div
                          className="risk-factor"
                          key={
                            factor.name ??
                            index
                          }
                        >

                          <div className="factor-header">

                            <span>
                              {factor.name}
                            </span>

                            <strong>
                              {value}
                            </strong>

                          </div>

                          <div className="factor-bar">

                            <div
                              style={{
                                width: `${Math.min(
                                  100,
                                  (value /
                                    maxRiskFactor) *
                                  100
                                )}%`,
                              }}
                            />

                          </div>

                          <small>
                            {factor.description}
                          </small>

                        </div>

                      );
                    }
                  )

                ) : (

                  <div className="empty-state">
                    Backend did not return risk
                    factor details.
                  </div>

                )}

              </div>

            </div>

            {/* FINDING */}

            <div className="panel finding-panel">

              <div className="panel-header">

                <div>

                  <div className="section-kicker">
                    VULNERABILITY
                  </div>

                  <h2>
                    {finding.vulnerability_id ??
                      finding.id ??
                      "Finding"}
                  </h2>

                </div>

                {finding.severity && (
                  <span
                    className={`status-pill ${getRiskClass(
                      finding.severity
                    )}`}
                  >
                    {finding.severity}
                  </span>
                )}

              </div>

              <div className="finding-details">

                {Object.entries(finding)
                  .filter(
                    ([key]) =>
                      ![
                        "risk",
                        "metadata",
                      ].includes(key)
                  )
                  .map(([key, value]) => (

                    <div key={key}>

                      <span>
                        {formatLabel(key)}
                      </span>

                      <strong>
                        {formatValue(value)}
                      </strong>

                    </div>

                  ))}

              </div>

              <div className="decision-box">

                <span className="label">
                  DECISION ENGINE
                </span>

                <strong>
                  {decision}
                </strong>

                <p>
                  {remediation}
                </p>

              </div>

            </div>

          </section>

        )}

        {/* ALL FINDINGS */}

        {findings.length > 1 && (

          <section className="panel">

            <div className="panel-header">

              <div>

                <div className="section-kicker">
                  SECURITY FINDINGS
                </div>

                <h2>
                  All Vulnerabilities
                </h2>

                <p>
                  Findings returned by the AEGIS
                  analysis engine.
                </p>

              </div>

            </div>

            <div className="finding-list">

              {findings.map(
                (item, index) => (

                  <div
                    className="finding-row"
                    key={
                      item.vulnerability_id ??
                      item.id ??
                      index
                    }
                  >

                    <div>

                      <strong>
                        {item.vulnerability_id ??
                          item.id ??
                          "Finding"}
                      </strong>

                      <span>
                        {item.asset ??
                          item.asset_id ??
                          "Unknown asset"}
                      </span>

                    </div>

                    <div>

                      <span>
                        Severity
                      </span>

                      <strong>
                        {item.severity ??
                          "—"}
                      </strong>

                    </div>

                    <div>

                      <span>
                        Risk
                      </span>

                      <strong>
                        {item.risk_score ??
                          item.risk ??
                          "—"}
                      </strong>

                    </div>

                    <div>

                      <span>
                        Priority
                      </span>

                      <strong>
                        {item.priority ??
                          "—"}
                      </strong>

                    </div>

                  </div>

                )
              )}

            </div>

          </section>

        )}

        {/* SECURITY LIFECYCLE */}

        <section className="panel">

          <div className="panel-header">

            <div>

              <div className="section-kicker">
                AUTONOMOUS SECURITY LOOP
              </div>

              <h2>
                Security Lifecycle
              </h2>

              <p>
                Current AEGIS security processing
                pipeline.
              </p>

            </div>

          </div>

          <div className="lifecycle">

            {getLifecycle(data).map(
              (step, index, array) => (

                <div
                  className="lifecycle-step"
                  key={
                    step.title ??
                    index
                  }
                >

                  <div className="lifecycle-number">
                    {String(
                      index + 1
                    ).padStart(2, "0")}
                  </div>

                  <div>

                    <strong>
                      {step.title}
                    </strong>

                    <span>
                      {step.description}
                    </span>

                  </div>

                  {index <
                    array.length - 1 && (

                      <div className="lifecycle-arrow">
                        →
                      </div>

                    )}

                </div>

              )
            )}

          </div>

        </section>

        {/* REMEDIATION */}

        {finding && (

          <section className="panel remediation-panel">

            <div className="panel-header">

              <div>

                <div className="section-kicker">
                  DECISION ENGINE
                </div>

                <h2>
                  Recommended Remediation
                </h2>

                <p>
                  Action generated by the AEGIS
                  decision engine.
                </p>

              </div>

              <span className="status-pill priority">
                {priority}
              </span>

            </div>

            <div className="remediation-box">

              <div className="remediation-icon">
                ⚡
              </div>

              <div className="remediation-content">

                <div className="action">
                  {decision}
                </div>

                <p>
                  {remediation}
                </p>

              </div>

            </div>

          </section>

        )}

      </main>

      <footer>
        AEGIS v0.1.0 · Autonomous Security
        Intelligence Platform
      </footer>

    </div>
  );
}

// ============================================================
// HELPERS
// ============================================================

function getNodeIcon(type) {
  const value =
    String(type || "").toUpperCase();

  const icons = {
    EXTERNAL: "◎",
    SERVICE: "◇",
    POD: "◇",
    DATABASE: "▣",
    SECRET: "◆",
    CONTAINER: "▢",
    HOST: "▤",
    USER: "●",
    IAM: "◈",
    BUCKET: "□",
  };

  return icons[value] ?? "◇";
}

function getRiskClass(level) {
  const value =
    String(level || "").toUpperCase();

  if (value === "CRITICAL") {
    return "critical";
  }

  if (value === "HIGH") {
    return "high";
  }

  if (value === "MEDIUM") {
    return "medium";
  }

  if (value === "LOW") {
    return "low";
  }

  return "";
}

function formatLabel(key) {
  return String(key)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) =>
      char.toUpperCase()
    );
}

function formatValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
}

function getLifecycle(data) {
  if (
    Array.isArray(
      data?.lifecycle
    )
  ) {
    return data.lifecycle;
  }

  if (
    Array.isArray(
      data?.security_lifecycle
    )
  ) {
    return data.security_lifecycle;
  }

  /*
   * These are only fallback labels.
   * The backend can override them by returning
   * lifecycle/security_lifecycle.
   */

  return [
    {
      title: "DETECT",
      description: "Finding identified",
    },
    {
      title: "ANALYZE",
      description: "Risk calculated",
    },
    {
      title: "DECIDE",
      description: "Priority assigned",
    },
    {
      title: "REMEDIATE",
      description: "Fix recommended",
    },
    {
      title: "VERIFY",
      description: "Resolution checked",
    },
    {
      title: "REASSESS",
      description: "Risk recalculated",
    },
  ];
}

export default App;