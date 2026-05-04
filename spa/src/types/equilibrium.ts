// TypeScript mirror of schema/equilibrium.schema.json. Kept hand-written rather
// than codegen so the SPA can compile without a build-time JSON-Schema pass.
// If the schema and these types drift, the validate script catches the data
// side and `tsc` catches the code side; the SPA build runs both before publish.

export const TACTICS = [
  "reconnaissance",
  "resource_development",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
] as const;
export type MitreTactic = (typeof TACTICS)[number];

export const MS_K8S_TACTICS = [
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "impact",
] as const;
export type MicrosoftK8sTactic = (typeof MS_K8S_TACTICS)[number];

export const VENDORS = [
  "wiz",
  "upwind",
  "lacework",
  "sysdig",
  "snowflake",
  "crowdstrike",
  "prisma_cloud",
  "orca",
  "datadog_cloud_siem",
] as const;
export type Vendor = (typeof VENDORS)[number];

export const QUERY_LANGUAGES = [
  "graphql",
  "wiz_resource_graph",
  "lql",
  "falco_yaml",
  "sql",
  "kql",
  "spl",
  "cql",
  "eql",
  "sigma",
  "osquery",
  "ebpf_dsl",
  "json_rule",
  "yaml_rule",
] as const;
export type QueryLanguage = (typeof QUERY_LANGUAGES)[number];

export type Confidence = "low" | "medium" | "high";

export interface DataComponent {
  id: string | null;
  name: string;
  data_source_id: string;
  data_source_name: string;
  definition?: string;
  url?: string;
  relevant_events?: string[];
}

export interface DetectionStrategy {
  id: string;
  name: string;
  summary?: string;
  url?: string;
  data_component_refs?: string[];
}

export interface MitreAttack {
  technique_id: string;
  name: string;
  tactics: MitreTactic[];
  sub_technique_of: string | null;
  platforms?: string[];
  url: string;
}

export interface MicrosoftK8sMatrix {
  id: string | null;
  name: string;
  tactic: MicrosoftK8sTactic;
  url?: string;
  description?: string;
}

export interface VendorDetection {
  vendor: Vendor;
  language: QueryLanguage;
  title: string;
  intent: string;
  query: string;
  required_telemetry: string[];
  mapped_data_components: string[];
  confidence: Confidence;
  false_positive_considerations?: string;
  limitations?: string;
  references?: string[];
}

export interface TechniqueRecord {
  id: string;
  title: string;
  description: string;
  tags?: string[];
  mitre_attack: MitreAttack;
  microsoft_k8s_matrix: MicrosoftK8sMatrix;
  data_components: DataComponent[];
  detection_strategies?: DetectionStrategy[];
  vendor_detections?: VendorDetection[];
  references?: string[];
  metadata: {
    version: string;
    schema_version?: string;
    created: string;
    updated: string;
    contributors?: string[];
  };
}
