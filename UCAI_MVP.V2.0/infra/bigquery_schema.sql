-- DATASET
CREATE SCHEMA IF NOT EXISTS `gen-lang-client-0591533880.uaci_data`
OPTIONS(location="US");

-- OCSF Security Events
CREATE TABLE IF NOT EXISTS `gen-lang-client-0591533880.uaci_data.ocsf_events` (
  event_uid STRING,
  time TIMESTAMP,
  severity_id INT64,
  severity STRING,
  class_uid INT64,
  class_name STRING,
  cloud_account_id STRING,
  cloud_provider STRING,
  resource_name STRING,
  resource_type STRING,
  finding_type STRING,
  finding_desc STRING,
  remediation_hint STRING,
  tags JSON,
  raw_data JSON,
  ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
)
PARTITION BY DATE(time)
CLUSTER BY cloud_provider, severity, finding_type;

-- FOCUS Billing
CREATE TABLE IF NOT EXISTS `gen-lang-client-0591533880.uaci_data.focus_billing` (
  billing_period_start TIMESTAMP,
  billing_period_end TIMESTAMP,
  provider_name STRING,
  account_id STRING,
  resource_id STRING,
  resource_name STRING,
  resource_type STRING,
  service_category STRING,
  service_name STRING,
  region STRING,
  billed_cost FLOAT64,
  effective_cost FLOAT64,
  usage_quantity FLOAT64,
  usage_unit STRING,
  billing_currency STRING,
  tags JSON,
  ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP()
)
PARTITION BY DATE(billing_period_start)
CLUSTER BY provider_name, service_category, account_id;

-- Risk Scores
CREATE TABLE IF NOT EXISTS `gen-lang-client-0591533880.uaci_data.risk_scores` (
  resource_id STRING,
  resource_name STRING,
  account_id STRING,
  cloud_provider STRING,
  likelihood FLOAT64,
  impact FLOAT64,
  detectability FLOAT64,
  internet_exposed BOOL,
  pii_adjacent BOOL,
  business_critical BOOL,
  ai_workload BOOL,
  rpn_score FLOAT64,
  finding_type STRING,
  finding_desc STRING,
  remediation_type STRING,
  compliance_controls JSON,
  calculated_at TIMESTAMP
)
PARTITION BY DATE(calculated_at)
CLUSTER BY finding_type, account_id;

-- Incidents
CREATE TABLE IF NOT EXISTS `gen-lang-client-0591533880.uaci_data.incidents` (
  incident_id STRING,
  title STRING,
  description STRING,
  severity STRING,
  status STRING,
  affected_service STRING,
  account_id STRING,
  root_cause STRING,
  rca_summary STRING,
  rpn_score FLOAT64,
  mttr_minutes INT64,
  created_at TIMESTAMP,
  resolved_at TIMESTAMP
)
PARTITION BY DATE(created_at);

-- Action Register (mirror of Firestore, for analytics)
CREATE TABLE IF NOT EXISTS `gen-lang-client-0591533880.uaci_data.action_register` (
  action_id STRING,
  agent_name STRING,
  action_type STRING,
  resource_id STRING,
  tier STRING,
  status STRING,
  approver_id STRING,
  rollback_executed BOOL,
  created_at TIMESTAMP
)
PARTITION BY DATE(created_at);

-- VIEWS

-- Top risks right now
CREATE OR REPLACE VIEW `gen-lang-client-0591533880.uaci_data.v_top_risks` AS
SELECT resource_name, cloud_provider, finding_type, rpn_score, remediation_type
FROM `gen-lang-client-0591533880.uaci_data.risk_scores`
WHERE calculated_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
ORDER BY rpn_score DESC LIMIT 25;

-- Daily cost by team
CREATE OR REPLACE VIEW `gen-lang-client-0591533880.uaci_data.v_daily_cost_by_team` AS
SELECT
  DATE(billing_period_start) AS date,
  JSON_VALUE(tags, '$.team') AS team,
  provider_name,
  service_category,
  ROUND(SUM(billed_cost), 2) AS total_cost
FROM `gen-lang-client-0591533880.uaci_data.focus_billing`
GROUP BY 1, 2, 3, 4
ORDER BY 1 DESC, 5 DESC;

-- RPN formula view
CREATE OR REPLACE VIEW `gen-lang-client-0591533880.uaci_data.v_rpn_scored` AS
SELECT
  resource_id, resource_name, finding_type,
  ROUND(
    (likelihood * impact * (1.0 / NULLIF(detectability, 0)))
    * IF(internet_exposed, 3.0, 1.0)
    * IF(pii_adjacent, 2.0, 1.0)
    * IF(business_critical, 2.0, 1.0)
    * IF(ai_workload, 1.5, 1.0), 2
  ) AS computed_rpn
FROM `gen-lang-client-0591533880.uaci_data.risk_scores`
ORDER BY computed_rpn DESC;
