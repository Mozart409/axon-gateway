// Generic layout invariants of the web UI. Each property walks the DOM in one
// `page.evaluate` and judges geometry, computed style, roles and attributes,
// never CSS class names. Code inside `evaluate` is self-contained: the helpers
// `describe` and `hidden` are repeated in every function on purpose.
import type { Page } from "@playwright/test";
import type { CheckContext, Property, Violation } from "./types";

/** At most this many offenders are reported per property. */
const MAX_OFFENDERS = 5;

/** Turns offender descriptors into violations of one property. */
function violations(property: string, message: string, offenders: string[]): Violation[] {
  return offenders.slice(0, MAX_OFFENDERS).map((o) => ({ property, detail: `${message}: ${o}` }));
}

/**
 * The page never scrolls sideways: the root scroll width fits the client
 * width (1px of rounding slack).
 */
async function noHorizontalScroll(page: Page): Promise<Violation[]> {
  const r = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  if (r.scrollWidth <= r.clientWidth + 1) return [];
  return [
    {
      property: "no-horizontal-scroll",
      detail: `document scrollWidth ${r.scrollWidth} > clientWidth ${r.clientWidth}`,
    },
  ];
}

/**
 * No rendered element sticks out of the viewport horizontally, unless an
 * ancestor below body clips or scrolls its overflow (a scroll container may
 * hold wider content).
 */
async function insideViewport(page: Page): Promise<Violation[]> {
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const clips = (el: Element): boolean => {
      for (let p = el.parentElement; p && p !== document.body && p !== document.documentElement; p = p.parentElement) {
        const ox = getComputedStyle(p).overflowX;
        if (ox === "auto" || ox === "scroll" || ox === "hidden" || ox === "clip") return true;
      }
      return false;
    };
    const width = window.innerWidth;
    const out: string[] = [];
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      if (out.length >= max) break;
      if (el.closest("symbol, defs") || el.closest("[popover]:not(:popover-open)")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const r = el.getBoundingClientRect();
      if (r.width <= 2 || r.height <= 2) continue;
      if (r.right <= width + 1 && r.left >= -1) continue;
      if (clips(el)) continue;
      out.push(`${describe(el)} (left ${Math.round(r.left)}, right ${Math.round(r.right)}, viewport ${width})`);
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("inside-viewport", "sticks out of the viewport", offenders);
}

/**
 * Sibling blocks never overlap by more than 2px in both axes. Only in-flow
 * block-level children are compared: inline boxes legitimately overlap when
 * they wrap, and positioned boxes are placed on purpose.
 */
async function noOverlappingBlocks(page: Page): Promise<Violation[]> {
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const displays = new Set(["block", "flex", "grid", "list-item", "table", "inline-flex", "inline-grid"]);
    const out: string[] = [];
    const parents: Element[] = [document.body, ...Array.from(document.body.querySelectorAll("*"))];
    for (const parent of parents) {
      if (out.length >= max) break;
      if (parent.closest("svg") || parent.closest("[popover]:not(:popover-open)")) continue;
      const boxes: { el: Element; r: DOMRect }[] = [];
      for (const child of Array.from(parent.children)) {
        const style = getComputedStyle(child);
        if (!displays.has(style.display)) continue;
        if (style.position !== "static" && style.position !== "relative") continue;
        const r = child.getBoundingClientRect();
        if (r.width <= 2 || r.height <= 2) continue;
        boxes.push({ el: child, r });
      }
      for (let i = 0; i < boxes.length && out.length < max; i++) {
        for (let j = i + 1; j < boxes.length && out.length < max; j++) {
          const a = boxes[i].r;
          const b = boxes[j].r;
          const dx = Math.min(a.right, b.right) - Math.max(a.left, b.left);
          const dy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
          if (dx > 2 && dy > 2) {
            out.push(`${describe(boxes[i].el)} overlaps ${describe(boxes[j].el)} by ${Math.round(dx)}x${Math.round(dy)}px`);
          }
        }
      }
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("no-overlapping-blocks", "sibling blocks overlap", offenders);
}

/**
 * Nothing inside `main` silently cuts off its own content: a box with hidden
 * or clipped overflow must not have more content than space (ellipsis and
 * line-clamp are deliberate truncation and exempt).
 */
async function noClippedContent(page: Page): Promise<Violation[]> {
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const cuts = (v: string) => v === "hidden" || v === "clip";
    const out: string[] = [];
    const main = document.querySelector("main");
    if (!main) return out;
    for (const el of Array.from(main.querySelectorAll("*"))) {
      if (out.length >= max) break;
      if (el.closest("svg") || el.closest("[popover]:not(:popover-open)")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none") continue;
      const r = el.getBoundingClientRect();
      if (r.width <= 2 || r.height <= 2) continue;
      if (
        cuts(style.overflowX) &&
        style.textOverflow !== "ellipsis" &&
        el.clientWidth > 0 &&
        el.scrollWidth > el.clientWidth + 2
      ) {
        out.push(`${describe(el)} (horizontal: scrollWidth ${el.scrollWidth} > clientWidth ${el.clientWidth})`);
        continue;
      }
      const clamp = style.getPropertyValue("-webkit-line-clamp");
      const clamped = clamp !== "" && clamp !== "none";
      if (cuts(style.overflowY) && !clamped && el.scrollHeight > el.clientHeight + 2) {
        out.push(`${describe(el)} (vertical: scrollHeight ${el.scrollHeight} > clientHeight ${el.clientHeight})`);
      }
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("no-clipped-content", "content is cut off", offenders);
}

/**
 * Every page offers a way to navigate: the main sidebar is visible, or (when
 * it is hidden on narrow screens) the "Open menu" button is.
 */
async function navigationReachable(page: Page): Promise<Violation[]> {
  const navVisible = await page.locator('nav[aria-label="Main"]').evaluateAll((els) =>
    els.some((el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && getComputedStyle(el).visibility !== "hidden";
    }),
  );
  if (navVisible) return [];
  if (await page.getByRole("button", { name: "Open menu" }).isVisible()) return [];
  return [
    {
      property: "navigation-reachable",
      detail: 'neither nav[aria-label="Main"] nor a button named "Open menu" is visible',
    },
  ];
}

/**
 * Every `<use href="#id">` points at an element that exists, so no icon
 * renders blank.
 */
async function iconsResolve(page: Page): Promise<Violation[]> {
  const missing = await page.evaluate(() => {
    const out: string[] = [];
    for (const use of Array.from(document.querySelectorAll("svg use"))) {
      const href = use.getAttribute("href") ?? use.getAttribute("xlink:href") ?? "";
      if (!href.startsWith("#")) continue;
      if (!document.getElementById(href.slice(1))) out.push(href);
    }
    return out;
  });
  return violations("icons-resolve", "icon reference has no matching id", missing);
}

/**
 * Text is never smaller than 11px: every visible element with a direct text
 * node has a computed font size of at least 11px.
 */
async function readableText(page: Page): Promise<Violation[]> {
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const skipTags = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "TITLE"]);
    const out: string[] = [];
    for (const el of Array.from(document.body.querySelectorAll("*"))) {
      if (out.length >= max) break;
      if (skipTags.has(el.tagName) || el.closest("svg") || el.closest("[popover]:not(:popover-open)")) continue;
      const hasText = Array.from(el.childNodes).some(
        (n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim() !== "",
      );
      if (!hasText) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const r = el.getBoundingClientRect();
      if (r.width <= 2 || r.height <= 2) continue;
      const size = parseFloat(style.fontSize);
      if (size < 11) out.push(`${describe(el)} (font-size ${size}px)`);
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("readable-text", "text is smaller than 11px", offenders);
}

/**
 * Content is capped on very wide screens: at 1920px and up, no direct child
 * of `main` has a content box wider than 1700px.
 */
async function readableMeasure(page: Page, ctx: CheckContext): Promise<Violation[]> {
  if (ctx.viewport.width < 1920) return [];
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const main = document.querySelector("main");
    if (!main) return [];
    const targets = main.children.length > 0 ? Array.from(main.children) : [main];
    const out: string[] = [];
    for (const el of targets) {
      const style = getComputedStyle(el);
      if (style.display === "none") continue;
      const r = el.getBoundingClientRect();
      const content =
        r.width -
        (parseFloat(style.paddingLeft) || 0) -
        (parseFloat(style.paddingRight) || 0) -
        (parseFloat(style.borderLeftWidth) || 0) -
        (parseFloat(style.borderRightWidth) || 0);
      if (content > 1700) out.push(`${describe(el)} (content width ${Math.round(content)}px)`);
      if (out.length >= max) break;
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("readable-measure", "content wider than 1700px", offenders);
}

/**
 * On phones (viewport under 640px) every visible control is at least 24x24px
 * (WCAG 2.5.8). Links count when they are not inline (inline links inside a
 * text run are exempt).
 */
async function touchTargets(page: Page, ctx: CheckContext): Promise<Violation[]> {
  if (ctx.viewport.width >= 640) return [];
  const offenders = await page.evaluate((max) => {
    const describe = (el: Element): string => {
      const parts = [el.tagName.toLowerCase()];
      if (el.id) parts.push(`#${el.id}`);
      const role = el.getAttribute("role");
      if (role) parts.push(`[role=${role}]`);
      const label = el.getAttribute("aria-label");
      if (label) parts.push(`[aria-label="${label}"]`);
      const text = (el.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 40);
      if (text) parts.push(`"${text}"`);
      return parts.join(" ");
    };
    const selector = [
      "button",
      "select",
      "summary",
      'input:not([type="checkbox"]):not([type="radio"]):not([type="hidden"])',
      "a",
    ].join(", ");
    const out: string[] = [];
    for (const el of Array.from(document.body.querySelectorAll(selector))) {
      if (out.length >= max) break;
      if (el.closest("svg") || el.closest("[popover]:not(:popover-open)")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (el.tagName === "A" && el.getAttribute("role") !== "button" && style.display === "inline") continue;
      const r = el.getBoundingClientRect();
      if (r.width <= 2 || r.height <= 2) continue;
      if (r.width < 24 - 0.01 || r.height < 24 - 0.01) {
        out.push(`${describe(el)} (${Math.round(r.width * 10) / 10}x${Math.round(r.height * 10) / 10}px)`);
      }
    }
    return out;
  }, MAX_OFFENDERS);
  return violations("touch-targets", "target smaller than 24x24px", offenders);
}

/** The tab has a real title: non-empty and not the 404 page's. */
async function documentTitle(page: Page): Promise<Violation[]> {
  const title = (await page.title()).trim();
  if (title !== "" && title !== "Page Not Found") return [];
  return [
    {
      property: "document-title",
      detail: title === "" ? "document title is empty" : `document title is "${title}"`,
    },
  ];
}

/** Exactly one visible `main` landmark per page. */
async function singleMain(page: Page): Promise<Violation[]> {
  const count = await page.evaluate(() => {
    const visible = new Set<Element>();
    for (const el of Array.from(document.querySelectorAll("main, [role='main']"))) {
      if (el.closest("[popover]:not(:popover-open)")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const r = el.getBoundingClientRect();
      if (r.width > 0 && r.height > 0) visible.add(el);
    }
    return visible.size;
  });
  if (count === 1) return [];
  return [{ property: "single-main", detail: `expected exactly 1 visible main landmark, found ${count}` }];
}

/** Every generic layout property, in reporting order. */
export const LAYOUT_PROPERTIES: Property[] = [
  { name: "no-horizontal-scroll", check: (page) => noHorizontalScroll(page) },
  { name: "inside-viewport", check: (page) => insideViewport(page) },
  { name: "no-overlapping-blocks", check: (page) => noOverlappingBlocks(page) },
  { name: "no-clipped-content", check: (page) => noClippedContent(page) },
  { name: "navigation-reachable", check: (page) => navigationReachable(page) },
  { name: "icons-resolve", check: (page) => iconsResolve(page) },
  { name: "readable-text", check: (page) => readableText(page) },
  { name: "readable-measure", check: (page, ctx) => readableMeasure(page, ctx) },
  { name: "touch-targets", check: (page, ctx) => touchTargets(page, ctx) },
  { name: "document-title", check: (page) => documentTitle(page) },
  { name: "single-main", check: (page) => singleMain(page) },
];

/** Runs every property against the page and concatenates the violations. */
export async function checkProperties(
  page: Page,
  ctx: CheckContext,
  props: Property[] = LAYOUT_PROPERTIES,
): Promise<Violation[]> {
  const all: Violation[] = [];
  for (const prop of props) {
    all.push(...(await prop.check(page, ctx)));
  }
  return all;
}
