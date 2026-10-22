import type { Schemas } from "@vv/api-client";

/** Form fields derived from a node type's parameter JSON Schema (Pydantic output). */
export type Reference = Schemas["ReferenceFieldOut"];

export type FieldKind =
  | { kind: "expr" }
  | { kind: "tpl" }
  | { kind: "enum"; options: string[] }
  | { kind: "const"; value: unknown }
  | { kind: "boolean" }
  | { kind: "number"; integer: boolean; min?: number; max?: number }
  | { kind: "string"; maxLength?: number; pattern?: string; format?: string }
  | { kind: "multi"; options: string[] }
  | { kind: "list" }
  | { kind: "reference"; ref: Reference }
  | { kind: "json" };

export type FieldSpec = FieldKind & {
  name: string;
  required: boolean;
  nullable: boolean;
  default?: unknown;
  title?: string;
  description?: string;
};

type JsonSchema = Record<string, unknown>;

function resolve(schema: JsonSchema, defs: Record<string, JsonSchema>): JsonSchema {
  const ref = schema.$ref;
  if (typeof ref === "string" && ref.startsWith("#/$defs/")) {
    return { ...(defs[ref.slice("#/$defs/".length)] ?? {}), ...omit(schema, "$ref") };
  }
  return schema;
}

function omit(schema: JsonSchema, key: string): JsonSchema {
  return Object.fromEntries(Object.entries(schema).filter(([k]) => k !== key));
}

function isDynamic(schema: JsonSchema, key: "$expr" | "$tpl"): boolean {
  const properties = schema.properties;
  return Boolean(properties && typeof properties === "object" && key in properties);
}

function kindOf(schema: JsonSchema): FieldKind {
  if (isDynamic(schema, "$expr")) return { kind: "expr" };
  if (isDynamic(schema, "$tpl")) return { kind: "tpl" };
  if ("const" in schema) return { kind: "const", value: schema.const };
  if (Array.isArray(schema.enum)) return { kind: "enum", options: schema.enum.map(String) };
  switch (schema.type) {
    case "boolean":
      return { kind: "boolean" };
    case "integer":
    case "number": {
      const spec: FieldKind = { kind: "number", integer: schema.type === "integer" };
      if (typeof schema.minimum === "number") spec.min = schema.minimum;
      if (typeof schema.maximum === "number") spec.max = schema.maximum;
      return spec;
    }
    case "string": {
      const spec: FieldKind = { kind: "string" };
      if (typeof schema.maxLength === "number") spec.maxLength = schema.maxLength;
      if (typeof schema.pattern === "string") spec.pattern = schema.pattern;
      if (typeof schema.format === "string") spec.format = schema.format;
      return spec;
    }
    case "array": {
      const items = (schema.items ?? {}) as JsonSchema;
      if (Array.isArray(items.enum)) return { kind: "multi", options: items.enum.map(String) };
      if (items.type === "string") return { kind: "list" };
      return { kind: "json" };
    }
    default:
      return { kind: "json" };
  }
}

export function fieldsOf(
  paramsSchema: Record<string, unknown>,
  references: Record<string, Reference> = {},
): FieldSpec[] {
  const defs = (paramsSchema.$defs ?? {}) as Record<string, JsonSchema>;
  const properties = (paramsSchema.properties ?? {}) as Record<string, JsonSchema>;
  const required = new Set(
    Array.isArray(paramsSchema.required) ? paramsSchema.required.map(String) : [],
  );
  return Object.entries(properties).map(([name, raw]) => {
    let schema = resolve(raw, defs);
    let nullable = false;
    if (Array.isArray(schema.anyOf)) {
      const options = (schema.anyOf as JsonSchema[]).map((s) => resolve(s, defs));
      const concrete = options.filter((s) => s.type !== "null");
      nullable = concrete.length < options.length;
      schema =
        concrete.length === 1 ? { ...omit(schema, "anyOf"), ...concrete[0] } : { type: "object" };
    }
    const reference = references[name];
    const kind: FieldKind = reference ? { kind: "reference", ref: reference } : kindOf(schema);
    const spec: FieldSpec = { ...kind, name, required: required.has(name), nullable };
    if ("default" in raw) spec.default = raw.default;
    if (typeof raw.title === "string") spec.title = raw.title;
    if (typeof raw.description === "string") spec.description = raw.description;
    return spec;
  });
}

/** The text of a dynamic value, whatever the params hold ({"$expr": …}, a literal…). */
export function dynamicText(value: unknown, key: "$expr" | "$tpl"): string {
  if (value && typeof value === "object" && key in value) {
    const text = (value as Record<string, unknown>)[key];
    return typeof text === "string" ? text : "";
  }
  return typeof value === "string" ? value : "";
}
