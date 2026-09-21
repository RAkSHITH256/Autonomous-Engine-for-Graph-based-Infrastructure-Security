import { useEffect, useMemo, useState } from "react";
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

  useEffect(() => {
    fetch(`${API_URL}/dashboard`)
      .then((response) => {
        if (!response.ok) {
          throw new Error(`API returned ${response.status}`);
        }

        return response.json();
      })
      .then((result) => {
        setData(result);
      })
      .catch((err) => {
        setError(err.message);
      });
  }, []);

  /*
   * ---------------------------------------------------------
   * Build graph from the attack path returned by AEGIS
   * ---------------------------------------------------------
   */

  const graph = useMemo(() => {
    if (!data?.attack_path?.nodes) {
      return {
        nodes: [],
        edges: [],
      };
    }

    const pathNodes = data.attack_path.nodes;

    const nodes = pathNodes.map((node, index) => {
      const isCritical = node.criticality === "CRITICAL";

      return {
        id: node.asset_id,

        position: {
          x: index * 240,
          y: 100,
        },

        data: {
          label: (
            <div
              className={`graph-node ${isCritical ? "graph-critical" : ""
                }`}
            >
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
          width: 180,
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
              ? "#ff4d5e"
              : "#64748b",
          strokeWidth: 2,
        },

        label: "ATTACK PATH",

        labelStyle: {
          fill: "#71808e",
          fontSize: 9,
        },

        labelBgStyle: {
          fill: "#111820",
        },
      });
    }

    return {
      nodes,
      edges,
    };
  }, [data]);

  if (error) {
    return (
      <div className="app">
        <header className="header">
          <div>
            <h1>AEGIS</h1>
            <p>
              Autonomous Engine for Graph-based Infrastructure Security
            </p>
          </div>
        </header>

        <div className="error">
          <h2>Backend connection failed</h2>

          <p>{error}</p>

          <p>
            Make sure FastAPI is running on
            <code> http://127.0.0.1:8000</code>.
          </p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="loading">
        <h1>AEGIS</h1>
        <p>Loading security intelligence...</p>
      </div>
    );
  }

  const summary = data.summary;
  const finding = data.findings?.[0];

  /*
   * ---------------------------------------------------------
   * Node click handler
   * ---------------------------------------------------------
   */

  const handleNodeClick = (_, node) => {
    const selected = data.attack_path.nodes.find(
      (item) => item.asset_id === node.id
    );

    setSelectedNode(selected || null);
  };

  return (
    <div className="app">

      {/* =====================================================
          HEADER
      ===================================================== */}

      <header className="header">

        <div>
          <h1>AEGIS</h1>

          <p>
            Autonomous Engine for Graph-based Infrastructure Security
          </p>
        </div>

        <div className="status">

          <span className="status-dot"></span>

          SYSTEM ONLINE

        </div>

      </header>


      <main>

        {/* =====================================================
            OVERVIEW
        ===================================================== */}

        <section className="overview">

          <div className="card risk-card">

            <span className="label">
              OVERALL RISK
            </span>

            <div className="risk-score">
              {summary.overall_risk}
            </div>

            <div className="risk-level">
              {summary.risk_level}
            </div>

          </div>


          <div className="card">

            <span className="label">
              FINDINGS
            </span>

            <div className="metric">
              {summary.finding_count}
            </div>

          </div>


          <div className="card">

            <span className="label">
              ATTACK PATH
            </span>

            <div className="metric">
              {data.attack_path?.path_length ?? 0}
            </div>

            <span className="muted">
              relationships
            </span>

          </div>


          <div className="card">

            <span className="label">
              STATUS
            </span>

            <div className="metric">
              ACTIVE
            </div>

            <span className="muted">
              Monitoring
            </span>

          </div>

        </section>


        {/* =====================================================
            INTERACTIVE ATTACK GRAPH
        ===================================================== */}

        <section className="panel graph-panel">

          <div className="panel-header">

            <div>

              <h2>
                Attack Graph
              </h2>

              <p>
                Interactive infrastructure attack-path analysis
              </p>

            </div>

            <span className="badge critical">
              {summary.risk_level}
            </span>

          </div>


          <div className="graph-container">

            <ReactFlow
              nodes={graph.nodes}
              edges={graph.edges}
              onNodeClick={handleNodeClick}
              fitView
              attributionPosition="bottom-left"
            >

              <Background />

              <Controls />

              <MiniMap />

            </ReactFlow>

          </div>

        </section>


        {/* =====================================================
            SELECTED NODE
        ===================================================== */}

        {selectedNode && (

          <section className="panel selected-node-panel">

            <div className="panel-header">

              <div>

                <h2>
                  Selected Asset
                </h2>

                <p>
                  Infrastructure node details
                </p>

              </div>

              <button
                className="close-button"
                onClick={() => setSelectedNode(null)}
              >
                ×
              </button>

            </div>


            <div className="selected-node-grid">

              <div>

                <span className="label">
                  ASSET ID
                </span>

                <strong>
                  {selectedNode.asset_id}
                </strong>

              </div>


              <div>

                <span className="label">
                  NAME
                </span>

                <strong>
                  {selectedNode.name}
                </strong>

              </div>


              <div>

                <span className="label">
                  TYPE
                </span>

                <strong>
                  {selectedNode.type}
                </strong>

              </div>


              <div>

                <span className="label">
                  CRITICALITY
                </span>

                <strong
                  className={
                    selectedNode.criticality === "CRITICAL"
                      ? "danger-text"
                      : ""
                  }
                >
                  {selectedNode.criticality || "UNKNOWN"}
                </strong>

              </div>

            </div>

          </section>

        )}


        {/* =====================================================
            SECURITY FINDING
        ===================================================== */}

        {finding && (

          <section className="panel">

            <div className="panel-header">

              <div>

                <h2>
                  Security Finding
                </h2>

                <p>
                  Contextual vulnerability analysis
                </p>

              </div>

              <span className="badge critical">
                {finding.risk_level}
              </span>

            </div>


            <div className="finding-grid">

              <div>

                <span className="label">
                  VULNERABILITY
                </span>

                <strong>
                  {finding.vulnerability_id}
                </strong>

              </div>


              <div>

                <span className="label">
                  ASSET
                </span>

                <strong>
                  {finding.asset}
                </strong>

              </div>


              <div>

                <span className="label">
                  SEVERITY
                </span>

                <strong>
                  {finding.severity}
                </strong>

              </div>


              <div>

                <span className="label">
                  CVSS
                </span>

                <strong>
                  {finding.cvss}
                </strong>

              </div>


              <div>

                <span className="label">
                  RISK SCORE
                </span>

                <strong>
                  {finding.risk_score}
                </strong>

              </div>


              <div>

                <span className="label">
                  PRIORITY
                </span>

                <strong>
                  {finding.priority}
                </strong>

              </div>

            </div>

          </section>

        )}


        {/* =====================================================
            REMEDIATION
        ===================================================== */}

        {finding && (

          <section className="panel remediation">

            <div className="panel-header">

              <div>

                <h2>
                  Recommended Remediation
                </h2>

                <p>
                  Decision Engine recommendation
                </p>

              </div>

              <span className="badge priority">
                {finding.priority}
              </span>

            </div>


            <div className="remediation-box">

              <div className="action">
                {finding.decision}
              </div>

              <p>
                {finding.remediation}
              </p>

            </div>

          </section>

        )}

      </main>


      <footer>

        AEGIS v0.1.0 · Security Intelligence Platform

      </footer>

    </div>
  );
}

export default App;