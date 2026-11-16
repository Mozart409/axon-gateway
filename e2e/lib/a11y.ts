// Accessibility property: axe-core against WCAG 2.0 to 2.2 level A and AA.
import AxeBuilder from "@axe-core/playwright";
import type { Property, Violation } from "./types";

/**
 * Axe rules switched off. A rule goes here only with a reason next to it.
 */
export const DISABLED_AXE_RULES: string[] = [];

/** At most this many nodes are reported per violated rule. */
const MAX_NODES_PER_RULE = 3;

/** No axe violation of WCAG 2.x A/AA on the page. */
export const AXE_PROPERTY: Property = {
  name: "axe",
  check: async (page) => {
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
      .disableRules(DISABLED_AXE_RULES)
      .analyze();
    const found: Violation[] = [];
    for (const rule of results.violations) {
      for (const node of rule.nodes.slice(0, MAX_NODES_PER_RULE)) {
        found.push({
          property: "axe",
          detail: `${rule.id} (${rule.impact}): ${node.target.join(" ")} — ${rule.help}`,
        });
      }
    }
    return found;
  },
};
