export type ExplanationFeature = {
  feature: string;
  impact: number;
  value?: string;
};

const toNumber = (value: unknown) => {
  const num = typeof value === "number" ? value : Number(value);
  return Number.isFinite(num) ? num : 0;
};

export function extractExplanationFeatures(shapeExplanation: string | null | undefined): ExplanationFeature[] {
  if (!shapeExplanation) return [];

  try {
    const parsed = JSON.parse(shapeExplanation);

    if (Array.isArray(parsed)) {
      return parsed
        .map((item: any) => ({
          feature: item?.feature || item?.name || "",
          impact: toNumber(item?.impact ?? item?.importance),
          value: item?.value != null ? String(item.value) : undefined,
        }))
        .filter((item: ExplanationFeature) => item.feature);
    }

    if (parsed && Array.isArray(parsed.features)) {
      return parsed.features
        .map((item: any) => ({
          feature: item?.feature || item?.name || "",
          impact: toNumber(item?.impact ?? item?.importance),
          value: item?.value != null ? String(item.value) : undefined,
        }))
        .filter((item: ExplanationFeature) => item.feature);
    }

    if (parsed && typeof parsed === "object") {
      return Object.entries(parsed).map(([feature, value]) => ({
        feature,
        impact: 0,
        value: value != null ? String(value) : undefined,
      }));
    }
  } catch (error) {
    console.warn("[AlertExplanation] Failed to parse shapeExplanation:", error);
  }

  return [];
}
