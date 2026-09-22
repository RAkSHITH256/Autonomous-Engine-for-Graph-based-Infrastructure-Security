import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_URL}/dashboard`);

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const result = await response.json();

      setData(result);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const graph = useMemo(() => {
    if (!data?.attack_path?.nodes) {
      return { nodes: [], edges: [] };
    }

    const pathNodes = data.attack_path.nodes;

    const nodes = pathNodes.map((node, index) => {
      const isCritical = node.criticality === "CRITICAL";

      return {
        id: node.asset_id,

        position: {
          x: index * 250,
          y: 100,
        },

        data: {
          label: (
            <div
              className={`graph-node ${isCritical ? "graph-critical" : ""
                }`}
            >
              <div className="graph-node-icon">
                {node.type === "EXTERNAL"
                  ? "◎"
                  : node.type === "DATABASE"
                    ? "▣"
                    : node.type === "SECRET"
                      ? "◆"
                      : "◇"}
              </div>

              <div className="graph-node-type">
                {node.type}
              </div>

              <div className="graph-node-name">
                {node.name}
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
      edges.push({
        id: `${pathNodes[i].asset_id}-${pathNodes[i + 1].asset_id}`,
        source: pathNodes[i].asset_id,
        target: pathNodes[i + 1].asset_id,
        animated: true,
        style: {
          stroke:
            pathNodes[i + 1].criticality === "CRITICAL"
              ? "#ff5364"
              : "#64748b",
          strokeWidth: 2,
        },
      });
    }

    return { nodes, edges };
  }, [data]);

  if (loading && !data) {
    return (
      <div className="loading-screen">
        <div className="loading-logo">AEGIS</div>
        <div className="loading-line" />
        <p>Loading security intelligence...</p>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="app">
        <header className="header">
          <div className="brand">
            <div className="brand-mark">A</div>
            <div>
              <h1>AEGIS</h1>
              <p>
                Autonomous Engine for Graph-based Infrastructure Security
              </p>
            </div>
          </div>
        </header>

        <main>
          <div className="error">
            <div className="error-icon">!</div>

            <div>
              <h2>Backend connection failed</h2>

              <p>{error}</p>

              <p className="muted">
                Make sure FastAPI is running on{" "}
                <code>{API_URL}</code>.
              </p>

              <button className="primary-button" onClick={loadDashboard}>
                Retry connection
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  const summary = data?.summary || {
    overall_risk: 0,
    risk_level: "LOW",
    finding_count: 0,
  };

  const finding = data?.findings?.[0];

  const riskScore = Number(summary.overall_risk || 0);

  const riskFactors = [
    {
      name: "Vulnerability severity",
      value: 30,
      description: "HIGH severity vulnerability",
    },
    {
      name: "Exploitability",
      value: 20,
      description: "HIGH exploitability",
    },
    {
      name: "External exposure",
      value: 20,
      description: "Internet-facing attack path",
    },
    {
      name: "Target criticality",
      value: 20,
      description: "Production DB is CRITICAL",
    },
    {
      name: "Path proximity",
      value: 6,
      description: "Short path to critical asset",
    },
  ];

  return (
    <div className="app">

      {/* HEADER */}

      <header className="header">
        <div className="brand">
          <div className="brand-mark">A</div>

          <div>
            <h1>AEGIS</h1>

            <p>
              Autonomous Engine for Graph-based Infrastructure Security
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
          >
            ↻
          </button>
        </div>
      </header>

      <main>

        {/* PAGE INTRO */}

        <section className="hero">
          <div>
            <div className="eyebrow">
              SECURITY OPERATIONS CENTER
            </div>

            <h2>Infrastructure Security Overview</h2>

            <p>
              Real-time graph-based analysis of vulnerabilities,
              attack paths and remediation decisions.
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

          <div className="risk-card card">
            <div className="card-top">
              <span className="label">OVERALL RISK</span>
              <span className="status-pill critical">
                {summary.risk_level}
              </span>
            </div>

            <div className="risk-display">
              <span className="risk-number">
                {riskScore}
              </span>
              <span className="risk-max">/100</span>
            </div>

            <div className="risk-meter">
              <div
                className="risk-meter-fill"
                style={{
                  width: `${Math.min(riskScore, 100)}%`,
                }}
              />
            </div>

            <p className="risk-caption">
              Critical infrastructure exposure detected
            </p>
          </div>

          <div className="metric-card card">
            <span className="label">FINDINGS</span>

            <div className="metric">
              {summary.finding_count}
            </div>

            <span className="metric-description">
              Vulnerabilities detected
            </span>
          </div>

          <div className="metric-card card">
            <span className="label">ATTACK PATH</span>

            <div className="metric">
              {data.attack_path?.path_length ?? 0}
            </div>

            <span className="metric-description">
              Nodes traversed
            </span>
          </div>

          <div className="metric-card card">
            <span className="label">PRIORITY</span>

            <div className="metric priority-value">
              {finding?.priority || "P3"}
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

              <h2>Attack Path</h2>

              <p>
                Trace the path from external exposure to
                critical infrastructure.
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
            <ReactFlow
              nodes={graph.nodes}
              edges={graph.edges}
              onNodeClick={(_, node) => {
                const selected =
                  data.attack_path.nodes.find(
                    (item) => item.asset_id === node.id
                  );

                setSelectedNode(selected || null);
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
                nodeColor={(node) =>
                  node.id ===
                    data.attack_path.nodes.find(
                      (n) =>
                        n.asset_id === node.id &&
                        n.criticality === "CRITICAL"
                    )?.asset_id
                    ? "#ff5364"
                    : "#64748b"
                }
              />
            </ReactFlow>
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

                <h2>{selectedNode.name}</h2>

                <p>Infrastructure node details</p>
              </div>

              <button
                className="close-button"
                onClick={() => setSelectedNode(null)}
              >
                ×
              </button>
            </div>

            <div className="selected-node-grid">

              <div className="detail-box">
                <span className="label">ASSET ID</span>
                <strong>{selectedNode.asset_id}</strong>
              </div>

              <div className="detail-box">
                <span className="label">TYPE</span>
                <strong>{selectedNode.type}</strong>
              </div>

              <div className="detail-box">
                <span className="label">NAME</span>
                <strong>{selectedNode.name}</strong>
              </div>

              <div className="detail-box">
                <span className="label">CRITICALITY</span>

                <strong
                  className={
                    selectedNode.criticality === "CRITICAL"
                      ? "danger-text"
                      : ""
                  }
                >
                  {selectedNode.criticality || "STANDARD"}
                </strong>
              </div>

            </div>
          </section>
        )}

        {/* RISK ANALYSIS */}

        {finding && (
          <section className="two-column">

            <div className="panel">

              <div className="panel-header">
                <div>
                  <div className="section-kicker">
                    RISK ENGINE
                  </div>

                  <h2>Why is this critical?</h2>
                </div>

                <span className="status-pill critical">
                  SCORE {finding.risk_score}
                </span>
              </div>

              <div className="risk-factors">

                {riskFactors.map((factor) => (
                  <div
                    className="risk-factor"
                    key={factor.name}
                  >
                    <div className="factor-header">
                      <span>{factor.name}</span>
                      <strong>{factor.value}</strong>
                    </div>

                    <div className="factor-bar">
                      <div
                        style={{
                          width: `${(factor.value / 30) * 100}%`,
                        }}
                      />
                    </div>

                    <small>{factor.description}</small>
                  </div>
                ))}

              </div>
            </div>

            {/* FINDING */}

            <div className="panel finding-panel">

              <div className="panel-header">
                <div>
                  <div className="section-kicker">
                    VULNERABILITY
                  </div>

                  <h2>{finding.vulnerability_id}</h2>
                </div>

                <span className="status-pill critical">
                  {finding.severity}
                </span>
              </div>

              <div className="vulnerability-id">
                {finding.vulnerability_id}
              </div>

              <div className="finding-details">

                <div>
                  <span>Asset</span>
                  <strong>{finding.asset}</strong>
                </div>

                <div>
                  <span>CVSS</span>
                  <strong>{finding.cvss}</strong>
                </div>

                <div>
                  <span>Risk</span>
                  <strong className="danger-text">
                    {finding.risk_score}
                  </strong>
                </div>

                <div>
                  <span>Priority</span>
                  <strong>{finding.priority}</strong>
                </div>

              </div>

              <div className="decision-box">
                <span className="label">
                  DECISION ENGINE
                </span>

                <strong>{finding.decision}</strong>

                <p>
                  Immediate remediation has been recommended
                  based on the calculated risk.
                </p>
              </div>

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

              <h2>Security Lifecycle</h2>

              <p>
                From vulnerability discovery through
                verification and reassessment.
              </p>
            </div>
          </div>

          <div className="lifecycle">

            {[
              ["01", "DETECT", "Finding identified"],
              ["02", "ANALYZE", "Risk calculated"],
              ["03", "DECIDE", "Priority assigned"],
              ["04", "REMEDIATE", "Fix recommended"],
              ["05", "VERIFY", "Resolution checked"],
              ["06", "REASSESS", "Risk recalculated"],
            ].map(([number, title, description], index) => (
              <div className="lifecycle-step" key={title}>

                <div className="lifecycle-number">
                  {number}
                </div>

                <div>
                  <strong>{title}</strong>
                  <span>{description}</span>
                </div>

                {index < 5 && (
                  <div className="lifecycle-arrow">
                    →
                  </div>
                )}

              </div>
            ))}

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

                <h2>Recommended Remediation</h2>

                <p>
                  Action generated from the current risk assessment.
                </p>
              </div>

              <span className="status-pill priority">
                {finding.priority}
              </span>
            </div>

            <div className="remediation-box">

              <div className="remediation-icon">
                ⚡
              </div>

              <div className="remediation-content">

                <div className="action">
                  {finding.decision}
                </div>

                <p>{finding.remediation}</p>

              </div>

            </div>

          </section>
        )}

      </main>

      <footer>
        AEGIS v0.1.0 · Autonomous Security Intelligence Platform
      </footer>
    </div>
  );
}

export default App;