import { Checkbox, SelectField, TextField } from "@vv/ui";

/** The subset of JSON Schema that connector configurations use (Pydantic models). */
interface Property {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  enum?: string[];
  minimum?: number;
  maximum?: number;
  anyOf?: Property[];
}

export interface ConfigSchema {
  properties?: Record<string, Property>;
  required?: string[];
}

export type ConfigValues = Record<string, string | number | boolean>;

function base(property: Property): Property {
  // "x: int | None" is rendered from its non-null branch.
  return property.anyOf?.find((p) => p.type !== "null") ?? property;
}

export function initialValues(
  schema: ConfigSchema,
  current?: Record<string, unknown>,
): ConfigValues {
  const values: ConfigValues = {};
  for (const [name, property] of Object.entries(schema.properties ?? {})) {
    const value = current?.[name] ?? property.default;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
      values[name] = value;
  }
  return values;
}

/** Form generated from the type's schema; values are validated again by the server. */
export function ConfigForm({
  schema,
  values,
  onChange,
}: {
  schema: ConfigSchema;
  values: ConfigValues;
  onChange: (values: ConfigValues) => void;
}) {
  const set = (name: string, value: string | number | boolean) =>
    onChange({ ...values, [name]: value });
  return (
    <>
      {Object.entries(schema.properties ?? {}).map(([name, raw]) => {
        const property = base(raw);
        const label = raw.title ?? property.title ?? name;
        const value = values[name];
        if (property.type === "boolean") {
          return (
            <Checkbox
              key={name}
              label={label}
              checked={Boolean(value)}
              onChange={(v) => set(name, v)}
            />
          );
        }
        if (property.enum) {
          return (
            <SelectField
              key={name}
              label={label}
              value={String(value ?? "")}
              onChange={(v) => set(name, v)}
              options={property.enum.map((e) => ({ value: e, label: e }))}
            />
          );
        }
        const numeric = property.type === "integer" || property.type === "number";
        const bounds = {
          ...(raw.description ? { hint: raw.description } : {}),
          ...(property.minimum !== undefined ? { min: property.minimum } : {}),
          ...(property.maximum !== undefined ? { max: property.maximum } : {}),
        };
        return (
          <TextField
            key={name}
            label={label}
            {...bounds}
            type={numeric ? "number" : "text"}
            step={property.type === "number" ? "any" : 1}
            value={value === undefined ? "" : String(value)}
            onChange={(e) => set(name, numeric ? Number(e.target.value) : e.target.value)}
          />
        );
      })}
    </>
  );
}
