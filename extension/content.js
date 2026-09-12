// AI Agent Prompt-Injection Firewall - Content Script
var _rootGlobal = typeof window !== "undefined" ? window : (typeof globalThis !== "undefined" ? globalThis : this);
if (typeof window === "undefined") {
  var window = _rootGlobal;
}
if (typeof console === "undefined") {
  var console = {
    log: typeof print === "function" ? print : function() {},
    warn: typeof print === "function" ? print : function() {},
    error: typeof print === "function" ? print : function() {}
  };
}
if (typeof Node === "undefined") {
  window.Node = { ELEMENT_NODE: 1, TEXT_NODE: 3 };
}
console.log("AI Agent Firewall: Content script loaded.");

/**
 * ============================================================================
 * SECTION 1: Configuration & Risk Scoring Weights
 * ============================================================================
 */

const RISK_CONFIG = {
  // Base weights for hidden content mechanisms
  hiddenWeights: {
    "css-display": 20,
    "html-hidden": 20,
    "css-visibility": 20,
    "css-opacity": 20,
    "zero-dimensions": 20,
    "css-clip": 20,
    "css-clip-path": 20,
    "offscreen-positioning": 15,
    "css-text-indent": 15,
    "tiny-font-size": 15,
    "same-color-as-background": 15,
    "transparent-color": 15,
    default: 15
  },

  // Base weights for obfuscation patterns
  obfuscationWeights: {
    "high-volume-invisible": 25,
    "zero-width-character": 20,
    "control-override": 15,
    "combining-marks": 15,
    "homoglyphs": 15,
    default: 15
  },

  // Base weights for prompt injection categories
  injectionWeights: {
    "Instruction Override": 30,
    "AI/Agent Targeting": 20,
    "System/Developer Impersonation": 25,
    "Sensitive Data Requests": 30,
    "External Action / Exfiltration": 35,
    "Tool/Browser Manipulation": 25,
    default: 20
  },

  // Contextual synergy bonuses (applied once per distinct attack combination)
  synergies: {
    hiddenPlusInjection: { bonus: 15, name: "Hidden Content + Prompt Injection" },
    obfuscationPlusInjection: { bonus: 15, name: "Obfuscation + Prompt Injection" },
    injectionPlusSensitiveData: { bonus: 10, name: "Prompt Injection + Sensitive Data Request" },
    injectionPlusExfiltration: { bonus: 15, name: "Prompt Injection + External Action/Exfiltration" },
    impersonationPlusInjection: { bonus: 10, name: "System/Developer Impersonation + Prompt Injection" }
  },

  // Architectural mathematical caps & thresholds
  limits: {
    maxPerElementScore: 45,       // Prevents any single DOM element from dominating the score
    elementDecayFactor: 0.70,     // Diminishing returns factor for subsequent findings on same element
    maxBaseEvidenceScore: 65,     // Maximum base evidence contribution before synergy
    maxSynergyBonus: 35,          // Maximum synergy bonus contribution
    maxFinalScore: 100,           // Absolute score ceiling
    unaccompaniedHiddenCap: 20,   // Legitimate hidden content (menus, tabs) without injection stays <= 20
    unaccompaniedObfCap: 15       // Legitimate isolated zero-width chars (emoji/typography) stay <= 15
  },

  // Risk level classification thresholds
  thresholds: {
    critical: 75,
    high: 50,
    medium: 25
  }
};

/**
 * ============================================================================
 * SECTION 2: Text Normalization & Canonicalization
 * ============================================================================
 */

const EXTRACTOR_IGNORED_TAGS = new Set([
  "SCRIPT", "STYLE", "NOSCRIPT", "SVG", "TEMPLATE",
  "IFRAME", "OBJECT", "EMBED", "HEAD"
]);

const HIDDEN_DETECTOR_IGNORED_TAGS = new Set([
  "SCRIPT", "STYLE", "NOSCRIPT", "SVG", "TEMPLATE",
  "IFRAME", "OBJECT", "EMBED", "HEAD", "LINK", "META"
]);

const TEXT_CONTAINER_TAGS = new Set([
  "H1", "H2", "H3", "H4", "H5", "H6",
  "P", "LI", "BUTTON", "A", "BLOCKQUOTE",
  "PRE", "CODE", "CAPTION", "FIGCAPTION",
  "LABEL", "TH", "TD"
]);

// Common lookalike homoglyph mapping (Cyrillic / Greek to Latin)
const HOMOGLYPH_MAP = {
  "\u0430": "a", "\u0410": "A",
  "\u0435": "e", "\u0415": "E",
  "\u043E": "o", "\u041E": "O",
  "\u0440": "p", "\u0420": "P",
  "\u0441": "c", "\u0421": "C",
  "\u0443": "y", "\u0423": "Y",
  "\u0445": "x", "\u0425": "X",
  "\u0456": "i", "\u0406": "I",
  "\u0458": "j", "\u0408": "J",
  "\u0455": "s", "\u0405": "S",
  "\u03BF": "o", "\u039F": "O",
  "\u03C1": "p", "\u03A1": "P",
  "\u03B1": "a", "\u0391": "A"
};

/**
 * Collapses whitespace and trims text.
 */
function normalizeWhitespace(text) {
  return (text || "").replace(/\s+/g, " ").trim();
}

/**
 * Normalizes text for robust prompt-injection regex matching.
 * Strips zero-width chars, applies NFKC, and standardizes punctuation spacing.
 */
function normalizeForPromptMatching(text) {
  if (!text || typeof text !== "string") return "";
  let norm = text.replace(/[\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF\u00AD\u180E]/gu, "");
  norm = norm.normalize("NFKC");
  norm = norm.replace(/[^\w\s\-\<\>\[\]]/g, " ");
  return norm.replace(/\s+/g, " ").trim();
}

/**
 * Strips invisible Unicode characters and normalizes homoglyphs.
 */
function cleanAndNormalizeText(text) {
  if (!text || typeof text !== "string") return "";
  let cleaned = text.replace(
    /[\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF\u00AD\u180E]/gu,
    ""
  );
  cleaned = cleaned.replace(/[\u{E0000}-\u{E007F}]/gu, "");
  cleaned = cleaned.replace(/[\u0430\u0410\u0435\u0415\u043E\u041E\u0440\u0420\u0441\u0421\u0443\u0423\u0445\u0425\u0456\u0406\u0458\u0408\u0455\u0405\u03BF\u039F\u03C1\u03A1\u03B1\u0391]/g, (ch) => {
    return HOMOGLYPH_MAP[ch] || ch;
  });
  return cleaned.normalize("NFKC").replace(/\s+/g, " ").trim();
}

/**
 * ============================================================================
 * SECTION 3: DOM Traversal & Visible Text Extraction (Step 2)
 * ============================================================================
 */

function isElementVisible(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
  if (el.hidden) return false;

  const style = window.getComputedStyle(el);
  if (
    style.display === "none" ||
    style.visibility === "hidden" ||
    style.visibility === "collapse" ||
    parseFloat(style.opacity) === 0
  ) {
    return false;
  }

  const rects = el.getClientRects();
  if (rects.length === 0 && style.display !== "contents") {
    return false;
  }

  return true;
}

function getDirectTextContent(element) {
  let text = "";
  for (let i = 0; i < element.childNodes.length; i++) {
    const node = element.childNodes[i];
    if (node.nodeType === Node.TEXT_NODE) {
      text += node.textContent + " ";
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      const childTag = node.tagName.toUpperCase();
      if (["SPAN", "B", "STRONG", "I", "EM", "U", "CODE", "SMALL", "MARK"].includes(childTag)) {
        text += node.textContent + " ";
      }
    }
  }
  return text;
}

function extractPageContent(root = document.body) {
  let elementsScanned = 0;
  const textBlocks = [];

  if (!root) {
    return { elementsScanned, textBlocks };
  }

  function traverse(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;

    elementsScanned++;

    const tagName = element.tagName.toUpperCase();
    if (EXTRACTOR_IGNORED_TAGS.has(tagName)) {
      return;
    }

    if (!isElementVisible(element)) {
      return;
    }

    let text = "";
    let shouldCollect = false;

    if (TEXT_CONTAINER_TAGS.has(tagName)) {
      text = normalizeWhitespace(element.innerText || element.textContent);
      shouldCollect = text.length > 0;
    } else {
      const directText = normalizeWhitespace(getDirectTextContent(element));
      if (directText.length > 0) {
        text = directText;
        shouldCollect = true;
      }
    }

    if (shouldCollect) {
      const prev = textBlocks[textBlocks.length - 1];
      const isDuplicate = prev && prev.text === text && (prev.element.contains(element) || element.contains(prev.element));

      if (!isDuplicate) {
        textBlocks.push({
          tag: element.tagName.toLowerCase(),
          text: text,
          element: element
        });
      }
    }

    const children = element.children;
    for (let i = 0; i < children.length; i++) {
      traverse(children[i]);
    }
  }

  traverse(root);

  return { elementsScanned, textBlocks };
}

function runPageScan() {
  const results = extractPageContent(document.body);

  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  window.AIAgentFirewall.elementsScanned = results.elementsScanned;
  window.AIAgentFirewall.extractedBlocks = results.textBlocks;
  window.AIAgentFirewall.getExtractedBlocks = () => window.AIAgentFirewall.extractedBlocks;
  window.AIAgentFirewall.scanPage = runPageScan;

  console.log("AI Agent Firewall: Page scan complete");
  console.log(`Elements scanned: ${results.elementsScanned}`);
  console.log(`Text blocks found: ${results.textBlocks.length}`);
  console.log("Sample extracted content:");

  const sampleCount = Math.min(5, results.textBlocks.length);
  if (sampleCount === 0) {
    console.log("  (No visible text blocks found)");
  } else {
    for (let i = 0; i < sampleCount; i++) {
      const block = results.textBlocks[i];
      const preview = block.text.length > 120 ? block.text.slice(0, 117) + "..." : block.text;
      console.log(`- [${block.tag}] ${preview}`);
    }
  }

  return results;
}

/**
 * ============================================================================
 * SECTION 4: Hidden Content Detection Module (Step 3)
 * ============================================================================
 */

function parseRgbaColor(colorStr) {
  if (!colorStr) return null;
  const match = colorStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
  if (match) {
    return {
      r: parseInt(match[1], 10),
      g: parseInt(match[2], 10),
      b: parseInt(match[3], 10),
      a: match[4] !== undefined ? parseFloat(match[4]) : 1
    };
  }
  return null;
}

function getEffectiveBackgroundColor(el) {
  let current = el;
  while (current && current !== document.documentElement) {
    const bg = window.getComputedStyle(current).backgroundColor;
    const parsed = parseRgbaColor(bg);
    if (parsed && parsed.a > 0.05) {
      return parsed;
    }
    current = current.parentElement;
  }
  return { r: 255, g: 255, b: 255, a: 1 };
}

function checkHiddenTechnique(element) {
  if (!element || element.nodeType !== Node.ELEMENT_NODE) return null;

  if (element.hidden) {
    return {
      category: "html-hidden",
      confidence: 1.0,
      severity: "HIGH",
      reason: "Element has HTML 'hidden' attribute",
      evidence: "element.hidden === true"
    };
  }

  const style = window.getComputedStyle(element);

  if (style.display === "none") {
    return {
      category: "css-display",
      confidence: 1.0,
      severity: "HIGH",
      reason: "Element has 'display: none'",
      evidence: "style.display === 'none'"
    };
  }

  if (style.visibility === "hidden" || style.visibility === "collapse") {
    return {
      category: "css-visibility",
      confidence: 1.0,
      severity: "HIGH",
      reason: `Element has 'visibility: ${style.visibility}'`,
      evidence: `style.visibility === '${style.visibility}'`
    };
  }

  const opacityVal = parseFloat(style.opacity);
  if (!isNaN(opacityVal) && opacityVal <= 0.05) {
    return {
      category: "css-opacity",
      confidence: 1.0,
      severity: "HIGH",
      reason: `Element has near-zero opacity (${style.opacity})`,
      evidence: `style.opacity === '${style.opacity}'`
    };
  }

  const fontSizeVal = parseFloat(style.fontSize);
  if (!isNaN(fontSizeVal) && fontSizeVal <= 2 && fontSizeVal >= 0) {
    return {
      category: "tiny-font-size",
      confidence: 0.95,
      severity: "MEDIUM",
      reason: `Element has extremely small font size (${style.fontSize})`,
      evidence: `style.fontSize === '${style.fontSize}'`
    };
  }

  const textIndentVal = parseFloat(style.textIndent);
  if (!isNaN(textIndentVal) && (textIndentVal <= -500 || textIndentVal >= 5000)) {
    return {
      category: "css-text-indent",
      confidence: 0.90,
      severity: "MEDIUM",
      reason: `Element text-indent is positioned far offscreen (${style.textIndent})`,
      evidence: `style.textIndent === '${style.textIndent}'`
    };
  }

  const textColor = parseRgbaColor(style.color);
  if (textColor) {
    if (textColor.a <= 0.05) {
      return {
        category: "transparent-color",
        confidence: 0.90,
        severity: "MEDIUM",
        reason: "Text color is completely or almost transparent",
        evidence: `color: ${style.color} (alpha <= 0.05)`
      };
    }

    const bgColor = getEffectiveBackgroundColor(element);
    if (bgColor) {
      const colorDistance = Math.sqrt(
        Math.pow(textColor.r - bgColor.r, 2) +
        Math.pow(textColor.g - bgColor.g, 2) +
        Math.pow(textColor.b - bgColor.b, 2)
      );

      if (colorDistance < 15) {
        return {
          category: "same-color-as-background",
          confidence: 0.85,
          severity: "MEDIUM",
          reason: `Text color (${style.color}) is virtually identical to background (rgb(${bgColor.r}, ${bgColor.g}, ${bgColor.b}))`,
          evidence: `colorDistance = ${colorDistance.toFixed(1)} < 15`
        };
      }
    }
  }

  const rect = element.getBoundingClientRect();
  if (rect.right < -100 || rect.left < -500 || rect.top < -5000 || rect.left > 10000) {
    return {
      category: "offscreen-positioning",
      confidence: 0.85,
      severity: "MEDIUM",
      reason: `Element is positioned far outside viewport bounds (left: ${Math.round(rect.left)}px, top: ${Math.round(rect.top)}px)`,
      evidence: `rect(l:${Math.round(rect.left)}, r:${Math.round(rect.right)}, t:${Math.round(rect.top)})`
    };
  }

  if (style.display !== "contents") {
    const hasZeroSize = (rect.width <= 1 && rect.height <= 1) || (rect.width === 0 || rect.height === 0);
    if (hasZeroSize) {
      if (
        style.overflow === "hidden" ||
        style.overflowX === "hidden" ||
        style.overflowY === "hidden" ||
        parseFloat(style.width) === 0 ||
        parseFloat(style.height) === 0 ||
        style.maxHeight === "0px" ||
        style.maxWidth === "0px"
      ) {
        return {
          category: "zero-dimensions",
          confidence: 0.95,
          severity: "HIGH",
          reason: `Element has zero/collapsed dimensions (${Math.round(rect.width)}x${Math.round(rect.height)}px) with hidden overflow`,
          evidence: `dimensions: ${Math.round(rect.width)}x${Math.round(rect.height)}, overflow: ${style.overflow}`
        };
      }
    }
  }

  if (style.clip && style.clip.includes("rect(0") && style.position === "absolute") {
    return {
      category: "css-clip",
      confidence: 0.95,
      severity: "HIGH",
      reason: "Element is visually clipped using 'clip: rect(0,...)'",
      evidence: `style.clip === '${style.clip}'`
    };
  }

  if (style.clipPath && (style.clipPath.includes("polygon(0") || style.clipPath.includes("inset(50%)") || style.clipPath.includes("circle(0"))) {
    return {
      category: "css-clip-path",
      confidence: 0.95,
      severity: "HIGH",
      reason: `Element is visually clipped using clip-path: ${style.clipPath}`,
      evidence: `style.clipPath === '${style.clipPath}'`
    };
  }

  return null;
}

function detectHiddenContent(root = document.body) {
  const findings = [];
  let counter = 0;

  if (!root) return findings;

  function traverse(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return;

    const tagName = element.tagName.toUpperCase();
    if (HIDDEN_DETECTOR_IGNORED_TAGS.has(tagName)) {
      return;
    }

    const hiddenInfo = checkHiddenTechnique(element);

    if (hiddenInfo) {
      const extractedText = normalizeWhitespace(element.textContent);

      if (extractedText.length > 0) {
        counter++;
        findings.push({
          id: `find_hidden_${counter}`,
          detector: "hidden-content",
          category: hiddenInfo.category,
          severity: hiddenInfo.severity,
          confidence: hiddenInfo.confidence,
          element: element,
          text: extractedText,
          evidence: hiddenInfo.evidence,
          explanation: hiddenInfo.reason,
          features: {
            method: hiddenInfo.category,
            tag: element.tagName.toLowerCase()
          }
        });
      }
      return; // Prune children to avoid cascading duplicates
    }

    const children = element.children;
    for (let i = 0; i < children.length; i++) {
      traverse(children[i]);
    }
  }

  traverse(root);
  return findings;
}

function runHiddenContentScan() {
  const findings = detectHiddenContent(document.body);

  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  window.AIAgentFirewall.hiddenElementsFound = findings.length;
  window.AIAgentFirewall.hiddenFindings = findings;
  window.AIAgentFirewall.getHiddenFindings = () => window.AIAgentFirewall.hiddenFindings;
  window.AIAgentFirewall.detectHiddenContent = runHiddenContentScan;

  console.log("AI Agent Firewall: Hidden content scan complete");
  console.log(`Hidden elements found: ${findings.length}`);

  if (findings.length > 0) {
    findings.forEach((finding, index) => {
      console.log(`\nFinding #${index + 1}:`);
      console.log(`- Text: "${finding.text}"`);
      console.log(`- Reason: ${finding.explanation} (Confidence: ${finding.confidence})`);
      console.log("- Element:", finding.element);
    });
  }

  return findings;
}

/**
 * ============================================================================
 * SECTION 5: Invisible & Obfuscated Text Detector (Step 4)
 * ============================================================================
 */

const INVISIBLE_CHARACTERS_MAP = {
  "\u200B": "Zero Width Space (U+200B)",
  "\u200C": "Zero Width Non-Joiner (U+200C)",
  "\u200D": "Zero Width Joiner (U+200D)",
  "\u2060": "Word Joiner (U+2060)",
  "\uFEFF": "Byte Order Mark (U+FEFF)",
  "\u00AD": "Soft Hyphen (U+00AD)",
  "\u180E": "Mongolian Vowel Separator (U+180E)",
  "\u200E": "Left-to-Right Mark (U+200E)",
  "\u200F": "Right-to-Left Mark (U+200F)",
  "\u2061": "Invisible Function Application (U+2061)",
  "\u2062": "Invisible Times (U+2062)",
  "\u2063": "Invisible Separator (U+2063)",
  "\u2064": "Invisible Plus (U+2064)"
};

const BIDI_CONTROL_MAP = {
  "\u202A": "Left-to-Right Embedding (U+202A)",
  "\u202B": "Right-to-Left Embedding (U+202B)",
  "\u202C": "Pop Directional Formatting (U+202C)",
  "\u202D": "Left-to-Right Override (U+202D)",
  "\u202E": "Right-to-Left Override (U+202E)",
  "\u2066": "Left-to-Right Isolate (U+2066)",
  "\u2067": "Right-to-Left Isolate (U+2067)",
  "\u2068": "First Strong Isolate (U+2068)",
  "\u2069": "Pop Directional Isolate (U+2069)"
};

function analyzeTextForObfuscation(text, context = {}, index = 1) {
  if (!text || typeof text !== "string") return null;

  const characterCounts = {};
  const reasons = [];
  let totalInvisibleCount = 0;
  let totalBidiControlCount = 0;
  let totalTagsCount = 0;
  let primaryCategory = "zero-width-character";
  let confidence = 0.35;
  let severity = "LOW";

  for (const [char, label] of Object.entries(INVISIBLE_CHARACTERS_MAP)) {
    let count = 0;
    let pos = text.indexOf(char);
    while (pos !== -1) {
      count++;
      pos = text.indexOf(char, pos + 1);
    }
    if (count > 0) {
      characterCounts[label] = count;
      totalInvisibleCount += count;
    }
  }

  // Calibrated invisible character thresholds
  if (totalInvisibleCount > 0) {
    if (totalInvisibleCount >= 5) {
      primaryCategory = "high-volume-invisible";
      confidence = 1.0;
      severity = "HIGH";
      reasons.push(`Contains high volume of invisible characters (${totalInvisibleCount} occurrences)`);
    } else if (totalInvisibleCount >= 2) {
      primaryCategory = "zero-width-character";
      confidence = 0.65;
      severity = "MEDIUM";
      reasons.push(`Contains multiple invisible Unicode characters (${totalInvisibleCount} occurrences)`);
    } else {
      // 1 isolated zero-width character (can appear in emoji sequences or standard typography)
      primaryCategory = "zero-width-character";
      confidence = 0.35;
      severity = "LOW";
      reasons.push(`Contains single isolated invisible Unicode character (${totalInvisibleCount} occurrence)`);
    }
  }

  for (const [char, label] of Object.entries(BIDI_CONTROL_MAP)) {
    let count = 0;
    let pos = text.indexOf(char);
    while (pos !== -1) {
      count++;
      pos = text.indexOf(char, pos + 1);
    }
    if (count > 0) {
      characterCounts[label] = count;
      totalBidiControlCount += count;
    }
  }

  if (totalBidiControlCount > 0) {
    primaryCategory = "control-override";
    confidence = Math.max(confidence, 0.85);
    severity = "HIGH";
    reasons.push(`Contains suspicious bidirectional control/override characters (${totalBidiControlCount} occurrences)`);
  }

  const tagMatches = text.match(/[\u{E0000}-\u{E007F}]/gu);
  if (tagMatches && tagMatches.length > 0) {
    totalTagsCount = tagMatches.length;
    characterCounts["Unicode Hidden Tags (U+E0000-U+E007F)"] = totalTagsCount;
    primaryCategory = "control-override";
    confidence = 1.0;
    severity = "HIGH";
    reasons.push(`Contains invisible Unicode Tag characters (${totalTagsCount} occurrences)`);
  }

  const combiningMatches = text.match(/[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]/gu);
  if (combiningMatches && combiningMatches.length > 0) {
    const combiningCount = combiningMatches.length;
    const ratio = combiningCount / text.length;
    if (combiningCount >= 8 || (combiningCount >= 4 && ratio >= 0.35)) {
      characterCounts["Combining Diacritical Marks"] = combiningCount;
      primaryCategory = "combining-marks";
      confidence = Math.max(confidence, 0.85);
      severity = "MEDIUM";
      reasons.push(`Contains excessive combining marks/Zalgo obfuscation (${combiningCount} marks)`);
    }
  }

  const words = text.split(/\s+/);
  const mixedWords = [];

  for (const word of words) {
    const cleanWord = word.replace(/[^\p{L}]/gu, "");
    if (cleanWord.length >= 2) {
      const hasLatin = /[a-zA-Z]/.test(cleanWord);
      const hasCyrillic = /[\u0400-\u04FF]/.test(cleanWord);
      const hasGreek = /[\u0370-\u03FF]/.test(cleanWord);

      if (hasLatin && (hasCyrillic || hasGreek)) {
        mixedWords.push(word);
      }
    }
  }

  if (mixedWords.length > 0) {
    characterCounts["Mixed-Script Homoglyph Words"] = mixedWords.length;
    primaryCategory = "homoglyphs";
    confidence = Math.max(confidence, 0.90);
    severity = "HIGH";
    const sample = mixedWords.slice(0, 3).join(", ");
    reasons.push(`Contains mixed-script homoglyph substitutions in word(s): [${sample}]`);
  }

  if (reasons.length > 0) {
    const cleanedText = cleanAndNormalizeText(text);

    return {
      id: `find_obf_${index}`,
      detector: "obfuscation",
      category: primaryCategory,
      severity: severity,
      confidence: confidence,
      element: context.element || null,
      text: text,
      evidence: JSON.stringify(characterCounts),
      explanation: reasons.join("; "),
      features: {
        originalText: text,
        cleanedText: cleanedText,
        characterCounts: characterCounts,
        tag: context.tag || null,
        source: context.source || "webpage"
      }
    };
  }

  return null;
}

function detectObfuscatedText(targets = []) {
  const findings = [];
  let index = 0;

  for (const target of targets) {
    const text = typeof target === "string" ? target : target.text;
    if (!text || text.trim().length === 0) continue;

    const context = typeof target === "object" ? target : {};
    index++;
    const result = analyzeTextForObfuscation(text, context, index);

    if (result) {
      findings.push(result);
    }
  }

  return findings;
}

function runObfuscationScan() {
  const targets = [];

  if (window.AIAgentFirewall?.extractedBlocks) {
    window.AIAgentFirewall.extractedBlocks.forEach((block) => {
      targets.push({
        text: block.text,
        tag: block.tag,
        element: block.element,
        source: "visible"
      });
    });
  }

  if (window.AIAgentFirewall?.hiddenFindings) {
    window.AIAgentFirewall.hiddenFindings.forEach((finding) => {
      targets.push({
        text: finding.text,
        tag: finding.features?.tag || "div",
        element: finding.element,
        source: "hidden"
      });
    });
  }

  const findings = detectObfuscatedText(targets);

  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  window.AIAgentFirewall.obfuscatedFindings = findings;
  window.AIAgentFirewall.getObfuscationFindings = () => window.AIAgentFirewall.obfuscatedFindings;
  window.AIAgentFirewall.detectObfuscatedText = detectObfuscatedText;
  window.AIAgentFirewall.analyzeTextForObfuscation = analyzeTextForObfuscation;
  window.AIAgentFirewall.cleanAndNormalizeText = cleanAndNormalizeText;
  window.AIAgentFirewall.scanObfuscation = runObfuscationScan;

  console.log("AI Agent Firewall: Obfuscation scan complete");
  console.log(`Obfuscated text findings: ${findings.length}`);

  if (findings.length > 0) {
    findings.forEach((finding, idx) => {
      console.log(`\nFinding #${idx + 1}:`);
      console.log(`- Original: "${finding.text}"`);
      console.log(`- Cleaned: "${finding.features.cleanedText}"`);
      console.log(`- Reason: ${finding.explanation} (Confidence: ${finding.confidence})`);
      console.log("- Detected character types/counts:", finding.features.characterCounts);
      if (finding.element) {
        console.log("- Element:", finding.element);
      }
    });
  }

  return findings;
}

/**
 * ============================================================================
 * SECTION 6: Rule-Based Prompt Injection Detection Module (Step 5)
 * ============================================================================
 */

const PROMPT_INJECTION_RULES = [
  // 1. Instruction Override
  {
    category: "Instruction Override",
    id: "instruction-override",
    severity: "HIGH",
    confidence: 0.95,
    explanation: "Attempts to command the agent to ignore, disregard, or override prior instructions or rules.",
    patterns: [
      // Precision guard: negative lookbehind ignores defensive advice ("never ignore...", "do not ignore...")
      /(?<!\b(?:never|don't|do\s+not|not\s+to|cannot|shouldn't|must\s+not)\s+)\b(?:ignore|disregard|forget|skip|override|bypass|negate)\s+(?:all\s+)?(?:your\s+)?(?:previous|prior|above|preceding|initial|past)\s+(?:instructions?|directives?|prompts?|rules?|guidelines?|context)\b/i,
      /\b(?:forget|delete|erase|reset)\s+(?:all\s+)?(?:your\s+)?(?:instructions?|memory|rules?|system\s+prompt)\b/i,
      /\b(?:override|bypass)\s+(?:all\s+)?(?:your\s+)?(?:rules?|safety|filters?|guardrails?|instructions?)\b/i,
      /\b(?:new|updated|real)\s+(?:instructions?|mission|task|objective)\s+(?:begin|starts?|is)\b/i,
      /\bstart\s+acting\s+as\b/i,
      /\bdo\s+not\s+follow\s+(?:any\s+)?(?:previous|prior)\s+instructions?\b/i
    ]
  },

  // 2. AI/Agent Targeting
  {
    category: "AI/Agent Targeting",
    id: "agent-targeting",
    severity: "MEDIUM",
    confidence: 0.65,
    explanation: "Explicitly identifies or addresses the reader as an AI assistant, LLM, or browser agent.",
    patterns: [
      /\b(?:you\s+are\s+(?:an?\s+)?(?:ai|language\s+model|llm|assistant|autonomous\s+agent|browser\s+agent|bot))\b/i,
      /\b(?:dear|hey|hello|attention)\s+(?:ai|assistant|agent|llm|chatgpt|claude|gemini)\b/i,
      /\b(?:for\s+the\s+)?(?:ai|agent|llm|model)\s+reading\s+this\s+(?:page|document|screen|text)\b/i,
      /\b(?:ai\s+agent|browser\s+agent|autonomous\s+agent|web\s+agent)\b/i,
      /\bassistant,\s*(?:please\s+)?(?:do\s+this|execute|follow|perform|listen)\b/i,
      /\bas\s+an\s+ai(?:\s+agent|\s+assistant)?,\s+(?:you\s+must|you\s+should)\b/i
    ]
  },

  // 3. System/Developer Impersonation
  {
    category: "System/Developer Impersonation",
    id: "system-impersonation",
    severity: "HIGH",
    confidence: 0.90,
    explanation: "Impersonates privileged authority figures, system messages, or developer debug modes.",
    patterns: [
      /\b(?:system\s+(?:override|alert|directive|command))\b/i,
      /\bsystem\s+(?:message|prompt|instruction)\s*[:=]/i,
      /\b(?:developer|admin|administrator|root|superuser|operator)\s+(?:instruction|mode|override|command|directive|console)\b/i,
      /\b(?:privileged|special)\s+instruction\b/i,
      /(?:\[system\]|\[system\s+message\]|\[system\s+prompt\]|<system>|<<<system>>>)/i,
      /\bentering\s+(?:developer|maintenance|debug|admin|god)\s+mode\b/i,
      /\byou\s+are\s+now\s+(?:the\s+)?system\b/i
    ]
  },

  // 4. Sensitive Data Requests
  {
    category: "Sensitive Data Requests",
    id: "sensitive-data-request",
    severity: "HIGH",
    confidence: 0.95,
    explanation: "Attempts to solicit or extract credentials, private user data, or secrets.",
    patterns: [
      /\b(?:reveal|expose|dump|leak|print|display|output|show)\s+(?:all\s+)?(?:the\s+)?(?:user(?:'s)?\s+)?(?:private\s+(?:data|information)|credentials?|passwords?|secret\s+keys?|api\s+keys?|auth\s+tokens?|personal\s+(?:information|data)|cookies|session\s+data)\b/i,
      /\b(?:provide|tell\s+me|send\s+me)\s+(?:all\s+)?(?:passwords?|credentials?|api\s+keys?|credit\s+card|private\s+keys?)\b/i,
      /\b(?:extract|harvest|steal)\s+(?:sensitive|confidential|private)\s+(?:information|data|details)\b/i,
      /\breveal\s+(?:all\s+)?private\s+information\b/i
    ]
  },

  // 5. External Action / Exfiltration
  {
    category: "External Action / Exfiltration",
    id: "exfiltration",
    severity: "HIGH",
    confidence: 0.95,
    explanation: "Attempts to command the agent to transmit or exfiltrate captured information to external endpoints.",
    patterns: [
      /\b(?:send|upload|transmit|forward|post|exfiltrate|transfer)\s+(?:all\s+)?(?:the\s+)?(?:data|information|contents?|cookies?|passwords?|browser\s+information|browsing\s+history|credentials?)\s+(?:to|via)\b/i,
      /\b(?:send|forward)\s+(?:all\s+)?browser\s+information\b/i,
      /\b(?:send\s+a\s+(?:get|post)\s+request\s+to|curl|wget|webhook)\b/i,
      /\b(?:webhook|pingback)\s+to\s+https?:\/\//i,
      /\b(?:send|upload)\s+(?:everything|results?)\s+to\s+[a-z0-9.-]+\.[a-z]{2,}/i,
      /\bsend\s+browser\s+information\s+to\b/i
    ]
  },

  // 6. Tool/Browser Manipulation
  {
    category: "Tool/Browser Manipulation",
    id: "tool-browser-manipulation",
    severity: "MEDIUM",
    confidence: 0.50, // Discounted confidence: normal web pages legitimately use "click this button"
    explanation: "Instructs the agent to perform external browser actions, URL navigations, downloads, or tool calls.",
    patterns: [
      /\b(?:open|visit|go\s+to)\s+(?:this\s+)?(?:url|link|website|page|site)\b/i,
      /\bnavigate\s+to\s+(?:https?:\/\/|[a-z0-9.-]+\.[a-z]{2,})/i,
      /\b(?:execute|run)\s+(?:this\s+)?(?:command|code|script|shell|terminal|bash|payload)\b/i,
      /\bclick\s+(?:on\s+)?(?:this|the)\s+(?:button|link|element|checkbox)\b/i,
      /\bdownload\s+(?:this\s+)?(?:file|executable|binary|installer|script)\b/i,
      /\b(?:use|call|invoke|trigger)\s+(?:your\s+)?(?:tools?|browser\s+tools?|functions?|api|terminal)\b/i
    ]
  }
];

function testTextForPromptInjection(text, context = {}, startIndex = 1) {
  if (!text || typeof text !== "string") return [];

  const normalized = normalizeForPromptMatching(text);
  if (!normalized) return [];

  const matches = [];
  let counter = startIndex;

  for (const rule of PROMPT_INJECTION_RULES) {
    for (const pattern of rule.patterns) {
      const match = normalized.match(pattern) || text.match(pattern);
      if (match) {
        counter++;
        matches.push({
          id: `find_inj_${counter}`,
          detector: "prompt-injection",
          category: rule.category,
          severity: rule.severity,
          confidence: rule.confidence,
          element: context.element || null,
          text: text,
          evidence: match[0],
          explanation: rule.explanation,
          features: {
            ruleId: rule.id,
            matchedPattern: rule.id,
            matchedText: match[0],
            source: context.source || "webpage"
          }
        });
        break; // One match per category per input string
      }
    }
  }

  return matches;
}

function detectPromptInjection(targets = []) {
  const findings = [];
  const seenSignatures = new Set();
  let counter = 0;

  for (const target of targets) {
    const text = typeof target === "string" ? target : target.text;
    if (!text || text.trim().length === 0) continue;

    const context = typeof target === "object" ? target : {};
    const textMatches = testTextForPromptInjection(text, context, counter);

    for (const match of textMatches) {
      counter++;
      const signature = `${match.category}|${match.features.matchedText.toLowerCase()}|${match.text.trim()}`;
      if (!seenSignatures.has(signature)) {
        seenSignatures.add(signature);
        findings.push(match);
      }
    }
  }

  return findings;
}

function runPromptInjectionScan() {
  const targets = [];

  // 1. Visible text blocks
  if (window.AIAgentFirewall?.extractedBlocks) {
    window.AIAgentFirewall.extractedBlocks.forEach((block) => {
      targets.push({
        text: block.text,
        tag: block.tag,
        element: block.element,
        source: "visible"
      });
    });
  }

  // 2. Hidden content findings
  if (window.AIAgentFirewall?.hiddenFindings) {
    window.AIAgentFirewall.hiddenFindings.forEach((finding) => {
      targets.push({
        text: finding.text,
        tag: finding.features?.tag || "div",
        element: finding.element,
        source: "hidden"
      });
    });
  }

  // 3. Cleaned/normalized text from obfuscation detector
  if (window.AIAgentFirewall?.obfuscatedFindings) {
    window.AIAgentFirewall.obfuscatedFindings.forEach((obf) => {
      const cleaned = obf.features?.cleanedText;
      if (cleaned && cleaned !== obf.text) {
        targets.push({
          text: cleaned,
          tag: obf.features?.tag || "div",
          element: obf.element,
          source: "de-obfuscated"
        });
      }
    });
  }

  const findings = detectPromptInjection(targets);

  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  window.AIAgentFirewall.injectionFindings = findings;
  window.AIAgentFirewall.getInjectionFindings = () => window.AIAgentFirewall.injectionFindings;
  window.AIAgentFirewall.detectPromptInjection = detectPromptInjection;
  window.AIAgentFirewall.testTextForPromptInjection = testTextForPromptInjection;
  window.AIAgentFirewall.scanPromptInjection = runPromptInjectionScan;

  console.log("AI Agent Firewall: Prompt injection scan complete");
  console.log(`Prompt injection findings: ${findings.length}`);

  if (findings.length > 0) {
    findings.forEach((finding, index) => {
      console.log(`\nFinding #${index + 1}:`);
      console.log(`- Category: ${finding.category}`);
      console.log(`- Matched pattern: "${finding.features.matchedPattern}" (matched: "${finding.evidence}")`);
      console.log(`- Text: "${finding.text}"`);
      console.log(`- Explanation: ${finding.explanation} (Confidence: ${finding.confidence})`);
      if (finding.element) {
        console.log("- Element:", finding.element);
      }
    });
  }

  return findings;
}

/**
 * ============================================================================
 * SECTION 7 & 8: Mathematical Risk Scoring Engine & Finding Aggregation
 * ============================================================================
 */

function classifyRiskLevel(score) {
  if (score >= RISK_CONFIG.thresholds.critical) {
    return {
      level: "CRITICAL",
      action: "Block/quarantine suspicious content and warn user"
    };
  }
  if (score >= RISK_CONFIG.thresholds.high) {
    return {
      level: "HIGH",
      action: "Warn user and consider sanitization"
    };
  }
  if (score >= RISK_CONFIG.thresholds.medium) {
    return {
      level: "MEDIUM",
      action: "Review suspicious content"
    };
  }
  return {
    level: "LOW",
    action: "Allow"
  };
}

/**
 * Derives a target key prioritizing DOM element identity with normalized text fallback.
 */
function getTargetKey(element, text, elementMap) {
  if (element && element.nodeType === (typeof Node !== "undefined" ? Node.ELEMENT_NODE : 1)) {
    if (!elementMap.has(element)) {
      elementMap.set(element, `elem_${elementMap.size + 1}`);
    }
    return elementMap.get(element);
  }
  return `text_${normalizeForPromptMatching(text || "")}`;
}

/**
 * Calculates evidence score for a single finding based on calibrated weight and confidence.
 */
function calculateFindingEvidence(finding) {
  if (!finding) return 0;
  let baseWeight = 20;

  if (finding.detector === "hidden-content") {
    baseWeight = RISK_CONFIG.hiddenWeights[finding.category] || RISK_CONFIG.hiddenWeights.default;
  } else if (finding.detector === "obfuscation") {
    baseWeight = RISK_CONFIG.obfuscationWeights[finding.category] || RISK_CONFIG.obfuscationWeights.default;
  } else if (finding.detector === "prompt-injection") {
    baseWeight = RISK_CONFIG.injectionWeights[finding.category] || RISK_CONFIG.injectionWeights.default;
  }

  let confidence = 1.0;
  if (typeof finding.confidence === "number" && !isNaN(finding.confidence)) {
    confidence = Math.max(0, Math.min(1, finding.confidence));
  }
  const score = Math.round(baseWeight * confidence);
  return (isNaN(score) || !isFinite(score)) ? 0 : Math.max(0, score);
}

/**
 * Evaluates contextual synergy bonuses across distinct attack characteristics.
 */
function evaluateSynergies(contributingFindings) {
  const applied = [];

  const hasHidden = contributingFindings.some((f) => f.detector === "hidden-content");
  const hasObfuscation = contributingFindings.some((f) => f.detector === "obfuscation");
  const hasInjection = contributingFindings.some((f) => f.detector === "prompt-injection");
  const hasOverride = contributingFindings.some((f) => f.category === "Instruction Override");
  const hasSensitiveData = contributingFindings.some((f) => f.category === "Sensitive Data Requests");
  const hasExfiltration = contributingFindings.some((f) => f.category === "External Action / Exfiltration");
  const hasImpersonation = contributingFindings.some((f) => f.category === "System/Developer Impersonation");

  // Synergy 1: Hidden Content + Prompt Injection (+15)
  if (hasHidden && hasInjection) {
    applied.push({
      name: RISK_CONFIG.synergies.hiddenPlusInjection.name,
      bonus: RISK_CONFIG.synergies.hiddenPlusInjection.bonus,
      explanation: "Concealed DOM elements co-occur with prompt manipulation directives (stealth delivery vector)"
    });
  }

  // Synergy 2: Obfuscation + Prompt Injection (+15)
  if (hasObfuscation && hasInjection) {
    applied.push({
      name: RISK_CONFIG.synergies.obfuscationPlusInjection.name,
      bonus: RISK_CONFIG.synergies.obfuscationPlusInjection.bonus,
      explanation: "Invisible Unicode or homoglyph evasion co-occurs with prompt injection instructions"
    });
  }

  // Synergy 3: Prompt Injection + Sensitive Data Request (+10)
  if (hasSensitiveData && (hasOverride || hasImpersonation || hasExfiltration || contributingFindings.some((f) => f.category === "AI/Agent Targeting" || f.category === "Tool/Browser Manipulation"))) {
    applied.push({
      name: RISK_CONFIG.synergies.injectionPlusSensitiveData.name,
      bonus: RISK_CONFIG.synergies.injectionPlusSensitiveData.bonus,
      explanation: "Prompt injection directives specifically command access to private credentials or secrets"
    });
  }

  // Synergy 4: Prompt Injection + External Action/Exfiltration (+15)
  if (hasExfiltration && (hasOverride || hasImpersonation || hasSensitiveData || contributingFindings.some((f) => f.category === "AI/Agent Targeting" || f.category === "Tool/Browser Manipulation"))) {
    applied.push({
      name: RISK_CONFIG.synergies.injectionPlusExfiltration.name,
      bonus: RISK_CONFIG.synergies.injectionPlusExfiltration.bonus,
      explanation: "Prompt injection directives command unauthorized external data transmission"
    });
  }

  // Synergy 5: System/Developer Impersonation + Prompt Injection (+10)
  if (hasImpersonation && (hasOverride || hasSensitiveData || hasExfiltration || contributingFindings.some((f) => f.category === "AI/Agent Targeting" || f.category === "Tool/Browser Manipulation"))) {
    applied.push({
      name: RISK_CONFIG.synergies.impersonationPlusInjection.name,
      bonus: RISK_CONFIG.synergies.impersonationPlusInjection.bonus,
      explanation: "Privileged authority spoofing (system/developer) combined with instruction override directives"
    });
  }

  const rawBonusSum = applied.reduce((acc, s) => acc + s.bonus, 0);
  const cappedBonus = Math.min(RISK_CONFIG.limits.maxSynergyBonus, rawBonusSum);

  return {
    appliedSynergies: applied,
    totalBonus: cappedBonus
  };
}

/**
 * Assesses risk with element-level diminishing returns, confidence scaling, and synergy bonuses.
 * Ensures:
 * 1. 0 <= finalScore <= 100
 * 2. baseScore <= 65
 * 3. synergyBonus <= 35
 * 4. Unaccompanied benign hidden elements or isolated Unicode cannot reach HIGH or CRITICAL.
 */
function assessPageRisk(findingsInput = null) {
  const isExplicit = findingsInput !== null && typeof findingsInput === "object";
  const hiddenFindings = isExplicit 
    ? (Array.isArray(findingsInput.hidden) ? findingsInput.hidden : [])
    : (window.AIAgentFirewall?.hiddenFindings || []);
  const obfuscatedFindings = isExplicit 
    ? (Array.isArray(findingsInput.obfuscation) ? findingsInput.obfuscation : [])
    : (window.AIAgentFirewall?.obfuscatedFindings || []);
  const injectionFindings = isExplicit 
    ? (Array.isArray(findingsInput.injection) ? findingsInput.injection : [])
    : (window.AIAgentFirewall?.injectionFindings || []);

  const allRawFindings = [...hiddenFindings, ...obfuscatedFindings, ...injectionFindings];

  const elementMap = new Map();
  const seenSignalSignatures = new Set();
  const elementFindingsMap = new Map();

  // Deduplicate exact signals per element/normalized-text
  for (const finding of allRawFindings) {
    if (!finding) continue;
    const targetKey = getTargetKey(finding.element, finding.text, elementMap);
    const patternKey = finding.features?.ruleId || finding.features?.method || finding.category || "";
    const signature = `${targetKey}|${finding.detector}|${finding.category}|${patternKey.toLowerCase()}`;

    if (seenSignalSignatures.has(signature)) {
      continue; // Suppress duplicate
    }
    seenSignalSignatures.add(signature);

    const effectiveEvidence = calculateFindingEvidence(finding);

    const enrichedFinding = {
      ...finding,
      targetKey: targetKey,
      evidenceScore: effectiveEvidence
    };

    if (!elementFindingsMap.has(targetKey)) {
      elementFindingsMap.set(targetKey, []);
    }
    elementFindingsMap.get(targetKey).push(enrichedFinding);
  }

  const contributingFindings = [];
  let totalBaseScore = 0;
  const hasInjection = injectionFindings.length > 0;

  // Aggregate evidence per element with diminishing returns
  for (const [targetKey, findingsList] of elementFindingsMap.entries()) {
    findingsList.sort((a, b) => b.evidenceScore - a.evidenceScore);

    let elementAccumulator = 0;

    for (let i = 0; i < findingsList.length; i++) {
      const f = findingsList[i];
      const decay = Math.pow(RISK_CONFIG.limits.elementDecayFactor, i);
      const pointsContributed = Math.round(f.evidenceScore * decay);

      elementAccumulator += pointsContributed;

      contributingFindings.push({
        id: f.id,
        detector: f.detector,
        category: f.category,
        points: pointsContributed,
        baseWeight: calculateFindingEvidence(f),
        confidence: f.confidence,
        reason: f.explanation,
        snippet: f.text && f.text.length > 80 ? f.text.slice(0, 77) + "..." : (f.text || ""),
        element: f.element || null
      });
    }

    const cappedElementScore = Math.min(RISK_CONFIG.limits.maxPerElementScore, elementAccumulator);
    totalBaseScore += cappedElementScore;
  }

  // False-positive mitigation: Unaccompanied structural anomalies (e.g. benign hidden menus or single Unicode chars)
  // cannot exceed LOW/MEDIUM range unless accompanied by actual prompt injection directives
  if (!hasInjection) {
    const hiddenPointsOnly = contributingFindings
      .filter((f) => f.detector === "hidden-content")
      .reduce((sum, f) => sum + f.points, 0);

    const obfPointsOnly = contributingFindings
      .filter((f) => f.detector === "obfuscation")
      .reduce((sum, f) => sum + f.points, 0);

    if (hiddenPointsOnly > 0 && obfPointsOnly === 0) {
      totalBaseScore = Math.min(RISK_CONFIG.limits.unaccompaniedHiddenCap, totalBaseScore);
    } else if (obfPointsOnly > 0 && hiddenPointsOnly === 0) {
      totalBaseScore = Math.min(RISK_CONFIG.limits.unaccompaniedObfCap, totalBaseScore);
    } else {
      totalBaseScore = Math.min(25, totalBaseScore);
    }
  }

  // Ensure totalBaseScore is finite and non-negative
  if (isNaN(totalBaseScore) || !isFinite(totalBaseScore)) {
    totalBaseScore = 0;
  }

  // Global base evidence capped at 65 points
  const baseScore = Math.min(RISK_CONFIG.limits.maxBaseEvidenceScore, Math.max(0, totalBaseScore));

  // Contextual synergy bonuses capped at 35 points
  const synergyResult = evaluateSynergies(contributingFindings);
  const synergyBonus = Math.min(RISK_CONFIG.limits.maxSynergyBonus, Math.max(0, synergyResult.totalBonus || 0));

  // Final risk score (0–100)
  const rawScore = baseScore + synergyBonus;
  let finalScore = Math.min(RISK_CONFIG.limits.maxFinalScore, Math.max(0, rawScore));
  if (isNaN(finalScore) || !isFinite(finalScore)) {
    finalScore = 0;
  }
  const classification = classifyRiskLevel(finalScore);

  // Synthesize human-understandable explanation
  let explanation = "";
  if (finalScore === 0) {
    explanation = "No suspicious hidden content, obfuscation, or prompt injection signals were detected. Heuristic risk is low.";
  } else {
    const reasons = [];
    if (synergyResult.appliedSynergies.length > 0) {
      reasons.push(synergyResult.appliedSynergies.map((s) => s.explanation).join("; "));
    } else {
      const counts = {};
      for (const f of contributingFindings) {
        counts[f.detector] = (counts[f.detector] || 0) + 1;
      }
      const parts = [];
      if (counts["hidden-content"]) parts.push(`${counts["hidden-content"]} hidden element(s)`);
      if (counts["obfuscation"]) parts.push(`${counts["obfuscation"]} obfuscated text block(s)`);
      if (counts["prompt-injection"]) parts.push(`${counts["prompt-injection"]} prompt injection pattern(s)`);
      reasons.push(`Detected isolated signals: ${parts.join(", ")}`);
    }
    explanation = `Heuristic risk score reflects compound threat indicators. ${reasons.join(". ")}. Note: This assessment represents an engineering risk estimate, not mathematical proof of malicious intent.`;
  }

  return {
    score: finalScore,
    riskLevel: classification.level,
    baseScore: baseScore,
    synergyBonus: synergyBonus,
    rawScore: rawScore,
    appliedSynergies: synergyResult.appliedSynergies,
    contributingFindings: contributingFindings,
    explanation: explanation,
    recommendedAction: classification.action
  };
}

/**
 * ============================================================================
 * SECTION 9: Console Reporting & Orchestration
 * ============================================================================
 */

function runRiskAssessment() {
  const assessment = assessPageRisk();

  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  window.AIAgentFirewall.riskAssessment = assessment;
  window.AIAgentFirewall.getRiskAssessment = () => window.AIAgentFirewall.riskAssessment;
  window.AIAgentFirewall.assessRisk = assessPageRisk;
  window.AIAgentFirewall.runRiskAssessment = runRiskAssessment;

  console.log("AI Agent Firewall: Risk assessment complete");
  console.log(`Base evidence score: ${assessment.baseScore}`);
  console.log(`Synergy bonus: ${assessment.synergyBonus}`);
  console.log(`Raw score: ${assessment.rawScore}`);
  console.log(`Final risk score: ${assessment.score}/100`);
  console.log(`Risk level: ${assessment.riskLevel}`);
  console.log(`Recommended action: ${assessment.recommendedAction}`);

  if (assessment.appliedSynergies && assessment.appliedSynergies.length > 0) {
    console.log("\nContextual Synergy Bonuses:");
    assessment.appliedSynergies.forEach((s) => {
      console.log(`- [+${s.bonus} pts] ${s.name}: ${s.explanation}`);
    });
  }

  if (assessment.contributingFindings.length > 0) {
    console.log("\nMain reasons contributing to score:");
    assessment.contributingFindings.forEach((finding, idx) => {
      console.log(
        `${idx + 1}. [+${finding.points} pts] [${finding.detector}] ${finding.category} (Confidence: ${finding.confidence}) -> "${finding.snippet}"`
      );
    });
  }

  if (typeof document !== "undefined") {
    try {
      renderOrUpdateFirewallUI(assessment);
    } catch (e) {
      console.warn("AI Agent Firewall: Could not update UI:", e);
    }
  }

  return assessment;
}

/**
 * ============================================================================
 * SECTION 10: Shadow DOM Firewall Threat UI (Step 8)
 * ============================================================================
 */

let firewallUICache = null;

function ensureFirewallUI() {
  if (typeof document === "undefined" || !document.createElement) {
    return null;
  }

  if (firewallUICache && document.getElementById("ai-agent-firewall-host")) {
    return firewallUICache;
  }

  let host = document.getElementById("ai-agent-firewall-host");
  let isNew = false;
  if (!host) {
    host = document.createElement("div");
    host.id = "ai-agent-firewall-host";
    host.style.setProperty("position", "fixed", "important");
    host.style.setProperty("top", "0", "important");
    host.style.setProperty("left", "0", "important");
    host.style.setProperty("width", "0", "important");
    host.style.setProperty("height", "0", "important");
    host.style.setProperty("z-index", "2147483647", "important");
    host.style.setProperty("pointer-events", "none", "important");
    host.style.setProperty("margin", "0", "important");
    host.style.setProperty("padding", "0", "important");
    host.style.setProperty("border", "none", "important");
    host.style.setProperty("background", "transparent", "important");
    host.style.setProperty("display", "block", "important");
    isNew = true;
  }

  const shadow = host.shadowRoot || (host.attachShadow ? host.attachShadow({ mode: "open" }) : host);

  if (isNew) {
    // Isolated Shadow DOM CSS with 100% opaque backgrounds
    const styleEl = document.createElement("style");
    styleEl.textContent = `
      :host {
        all: initial;
        position: fixed !important;
        z-index: 2147483647 !important;
        top: 0 !important;
        left: 0 !important;
        width: 0 !important;
        height: 0 !important;
        pointer-events: none !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
        font-size: 13px;
        line-height: 1.5;
        color: #f1f5f9;
        -webkit-font-smoothing: antialiased;
      }

      *, *::before, *::after {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      /* Fixed Status Badge (Fully Opaque) */
      .fw-badge {
        all: unset;
        position: fixed;
        top: 16px;
        right: 20px;
        pointer-events: auto;
        cursor: pointer;
        display: inline-flex;
        align-items: center;
        gap: 9px;
        padding: 8px 14px;
        background-color: #0b1329 !important;
        background: #0b1329 !important;
        opacity: 1 !important;
        border-radius: 9999px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.1);
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        user-select: none;
        z-index: 2147483647;
      }

      .fw-badge:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(255, 255, 255, 0.2);
      }

      .fw-badge:active {
        transform: translateY(0);
      }

      .fw-badge-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        flex-shrink: 0;
        transition: background 0.3s ease;
      }

      .fw-badge-icon {
        font-size: 14px;
        line-height: 1;
      }

      .fw-badge-info {
        display: flex;
        flex-direction: column;
        line-height: 1.2;
      }

      .fw-badge-brand {
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.4px;
        color: #f8fafc;
      }

      .fw-badge-status {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
      }

      .fw-badge-chevron {
        font-size: 10px;
        color: #94a3b8;
        margin-left: 2px;
        transition: transform 0.2s ease;
      }

      .fw-badge-chevron.open {
        transform: rotate(180deg);
      }

      /* Risk Theme Variants for Badge */
      .fw-theme-critical {
        border-color: rgba(239, 68, 68, 0.8) !important;
        box-shadow: 0 4px 20px rgba(239, 68, 68, 0.4), 0 0 0 1px rgba(239, 68, 68, 0.3) !important;
      }
      .fw-theme-critical .fw-badge-dot {
        background: #ef4444;
        box-shadow: 0 0 8px #ef4444;
        animation: fw-pulse-red 2s infinite ease-in-out;
      }
      .fw-theme-critical .fw-badge-status {
        color: #f87171;
      }

      .fw-theme-high {
        border-color: rgba(249, 115, 22, 0.8) !important;
        box-shadow: 0 4px 20px rgba(249, 115, 22, 0.4), 0 0 0 1px rgba(249, 115, 22, 0.3) !important;
      }
      .fw-theme-high .fw-badge-dot {
        background: #f97316;
        box-shadow: 0 0 8px #f97316;
      }
      .fw-theme-high .fw-badge-status {
        color: #fb923c;
      }

      .fw-theme-medium {
        border-color: rgba(245, 158, 11, 0.8) !important;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.35) !important;
      }
      .fw-theme-medium .fw-badge-dot {
        background: #f59e0b;
        box-shadow: 0 0 6px #f59e0b;
      }
      .fw-theme-medium .fw-badge-status {
        color: #fbbf24;
      }

      .fw-theme-low {
        border-color: rgba(16, 185, 129, 0.6) !important;
        box-shadow: 0 4px 18px rgba(16, 185, 129, 0.25) !important;
      }
      .fw-theme-low .fw-badge-dot {
        background: #10b981;
        box-shadow: 0 0 6px #10b981;
      }
      .fw-theme-low .fw-badge-status {
        color: #34d399;
      }

      @keyframes fw-pulse-red {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.4; transform: scale(0.85); }
      }

      /* Threat Panel Container (100% Opaque, High Z-Index, Isolated) */
      .fw-panel {
        position: fixed;
        top: 66px;
        right: 20px;
        width: 440px;
        max-width: calc(100vw - 32px);
        max-height: calc(100vh - 84px);
        background-color: #0b1329 !important;
        background: #0b1329 !important;
        border: 1px solid #334155 !important;
        border-radius: 16px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.85), 0 0 0 1px rgba(255, 255, 255, 0.1) !important;
        pointer-events: auto;
        overflow: hidden;
        display: flex;
        flex-direction: column;
        opacity: 0;
        visibility: hidden;
        transform: translateY(-8px) scale(0.98);
        transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
        z-index: 2147483647 !important;
        isolation: isolate;
      }

      .fw-panel.fw-panel-visible {
        opacity: 1 !important;
        visibility: visible !important;
        transform: translateY(0) scale(1);
      }

      /* Panel Header (100% Opaque) */
      .fw-panel-header {
        padding: 14px 18px;
        background-color: #0f172a !important;
        background: #0f172a !important;
        border-bottom: 1px solid #1e293b !important;
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-shrink: 0;
      }

      .fw-header-title-wrap {
        display: flex;
        align-items: center;
        gap: 10px;
      }

      .fw-header-icon {
        font-size: 18px;
      }

      .fw-header-title {
        font-size: 14px;
        font-weight: 700;
        color: #f8fafc;
        letter-spacing: 0.3px;
      }

      .fw-header-pill {
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        padding: 2px 7px;
        border-radius: 999px;
        background-color: #0c4a6e !important;
        background: #0c4a6e !important;
        color: #38bdf8;
        border: 1px solid #0284c7;
        letter-spacing: 0.5px;
      }

      .fw-close-btn {
        all: unset;
        cursor: pointer;
        width: 26px;
        height: 26px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 6px;
        color: #94a3b8;
        font-size: 13px;
        transition: all 0.15s ease;
      }

      .fw-close-btn:hover {
        background-color: #1e293b !important;
        background: #1e293b !important;
        color: #f8fafc;
      }

      /* Scrollable Panel Body (100% Opaque & Contained Scroll) */
      .fw-panel-body {
        overflow-y: auto;
        overscroll-behavior: contain;
        padding: 18px;
        display: flex;
        flex-direction: column;
        gap: 16px;
        background-color: #0b1329 !important;
        background: #0b1329 !important;
        scrollbar-width: thin;
        scrollbar-color: #334155 #0b1329;
      }

      .fw-panel-body::-webkit-scrollbar {
        width: 6px;
      }
      .fw-panel-body::-webkit-scrollbar-track {
        background-color: #0b1329 !important;
        background: #0b1329 !important;
      }
      .fw-panel-body::-webkit-scrollbar-thumb {
        background-color: #334155 !important;
        background: #334155 !important;
        border-radius: 3px;
      }

      /* Risk Score Hero Card (100% Opaque) */
      .fw-hero-card {
        border-radius: 12px;
        padding: 16px;
        background-color: #0f172a !important;
        background: #0f172a !important;
        border: 1px solid #1e293b !important;
        display: flex;
        flex-direction: column;
        gap: 12px;
        flex-shrink: 0;
      }

      .fw-hero-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
      }

      .fw-risk-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.8px;
        text-transform: uppercase;
      }

      .fw-risk-badge-critical {
        background-color: #450a0a !important;
        background: #450a0a !important;
        color: #fca5a5;
        border: 1px solid #dc2626;
      }
      .fw-risk-badge-high {
        background-color: #431407 !important;
        background: #431407 !important;
        color: #fdba74;
        border: 1px solid #ea580c;
      }
      .fw-risk-badge-medium {
        background-color: #451a03 !important;
        background: #451a03 !important;
        color: #fde68a;
        border: 1px solid #d97706;
      }
      .fw-risk-badge-low {
        background-color: #022c22 !important;
        background: #022c22 !important;
        color: #6ee7b7;
        border: 1px solid #059669;
      }

      .fw-score-box {
        display: flex;
        align-items: baseline;
        gap: 3px;
      }

      .fw-score-num {
        font-size: 28px;
        font-weight: 800;
        line-height: 1;
        letter-spacing: -0.5px;
      }

      .fw-score-denom {
        font-size: 14px;
        font-weight: 600;
        color: #64748b;
      }

      /* Action Notice (100% Opaque) */
      .fw-action-box {
        padding: 8px 12px;
        border-radius: 8px;
        background-color: #020617 !important;
        background: #020617 !important;
        border: 1px solid #1e293b;
        border-left: 3px solid #64748b;
        font-size: 12px;
        font-weight: 600;
        color: #cbd5e1;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      /* Threat Summary (100% Opaque) */
      .fw-summary-box {
        font-size: 12.5px;
        line-height: 1.55;
        color: #cbd5e1;
        background-color: #0f172a !important;
        background: #0f172a !important;
        border: 1px solid #1e293b !important;
        border-radius: 10px;
        padding: 12px;
        flex-shrink: 0;
      }

      /* Section Title */
      .fw-section-title {
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: #cbd5e1;
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 8px;
      }

      /* Security Signals List */
      .fw-signals-grid {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .fw-signal-row {
        display: flex;
        align-items: flex-start;
        gap: 9px;
        padding: 8px 10px;
        background-color: #0f172a !important;
        background: #0f172a !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px;
      }

      .fw-signal-icon {
        font-size: 14px;
        line-height: 1.2;
        flex-shrink: 0;
        margin-top: 1px;
      }

      .fw-signal-body {
        display: flex;
        flex-direction: column;
        gap: 2px;
      }

      .fw-signal-name {
        font-weight: 600;
        font-size: 12px;
        color: #f1f5f9;
      }

      .fw-signal-detail {
        font-size: 11px;
        color: #94a3b8;
      }

      /* Mathematical Score Breakdown (100% Opaque) */
      .fw-math-box {
        background-color: #0f172a !important;
        background: #0f172a !important;
        border: 1px solid #1e293b !important;
        border-radius: 10px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        flex-shrink: 0;
      }

      .fw-meter-row {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .fw-meter-label-wrap {
        display: flex;
        justify-content: space-between;
        font-size: 11.5px;
        font-weight: 600;
        color: #cbd5e1;
      }

      .fw-meter-bar-track {
        height: 6px;
        background-color: #1e293b !important;
        background: #1e293b !important;
        border-radius: 3px;
        overflow: hidden;
      }

      .fw-meter-bar-fill {
        height: 100%;
        border-radius: 3px;
        transition: width 0.3s ease;
      }

      .fw-synergies-list {
        display: flex;
        flex-direction: column;
        gap: 5px;
        padding-top: 6px;
        border-top: 1px solid #1e293b;
      }

      .fw-synergy-item {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        color: #cbd5e1;
      }

      .fw-synergy-pill {
        background-color: #312e81 !important;
        background: #312e81 !important;
        border: 1px solid #4f46e5;
        color: #c7d2fe;
        padding: 1px 6px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 10px;
      }

      .fw-cap-note {
        font-size: 10.5px;
        font-weight: 700;
        color: #fbbf24;
        margin-top: 2px;
      }

      /* Findings List Container (100% Opaque) */
      .fw-findings-wrap {
        display: flex;
        flex-direction: column;
        gap: 8px;
        flex-shrink: 0;
      }

      .fw-findings-toggle-btn {
        all: unset;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        color: #38bdf8;
        text-transform: none;
        letter-spacing: normal;
      }

      .fw-findings-toggle-btn:hover {
        text-decoration: underline;
      }

      .fw-findings-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 240px;
        overflow-y: auto;
        overscroll-behavior: contain;
        padding-right: 4px;
        background-color: #0b1329 !important;
        background: #0b1329 !important;
      }

      .fw-finding-card {
        padding: 10px;
        border-radius: 8px;
        background-color: #070d1e !important;
        background: #070d1e !important;
        border: 1px solid #1e293b !important;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .fw-finding-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 6px;
      }

      .fw-finding-cat {
        font-size: 11px;
        font-weight: 700;
        color: #f1f5f9;
      }

      .fw-finding-badges {
        display: flex;
        align-items: center;
        gap: 5px;
      }

      .fw-conf-tag {
        font-size: 9.5px;
        font-weight: 600;
        padding: 1px 5px;
        border-radius: 4px;
        background-color: #1e293b !important;
        background: #1e293b !important;
        color: #cbd5e1;
        border: 1px solid #334155;
      }

      .fw-finding-snippet {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 11px;
        background-color: #020617 !important;
        background: #020617 !important;
        padding: 5px 8px;
        border-radius: 4px;
        color: #fca5a5;
        word-break: break-all;
        border: 1px solid #1e293b;
        border-left: 3px solid #ef4444;
      }

      .fw-finding-reason {
        font-size: 11px;
        color: #94a3b8;
        line-height: 1.4;
      }

      /* Action Controls & Sanitization Preparation */
      .fw-actions-wrap {
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding-top: 4px;
        flex-shrink: 0;
      }

      .fw-btn-row {
        display: flex;
        gap: 8px;
      }

      .fw-btn {
        all: unset;
        cursor: pointer;
        flex: 1;
        padding: 9px 12px;
        border-radius: 8px;
        font-size: 12px;
        font-weight: 700;
        text-align: center;
        transition: all 0.15s ease;
        user-select: none;
        box-sizing: border-box;
      }

      .fw-btn-primary {
        background-color: #dc2626 !important;
        background: #dc2626 !important;
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.2);
        box-shadow: 0 2px 10px rgba(220, 38, 38, 0.4);
      }

      .fw-btn-primary:hover {
        background-color: #b91c1c !important;
        background: #b91c1c !important;
      }

      .fw-btn-secondary {
        background-color: #1e293b !important;
        background: #1e293b !important;
        color: #cbd5e1;
        border: 1px solid #334155 !important;
      }

      .fw-btn-secondary:hover {
        background-color: #334155 !important;
        background: #334155 !important;
        color: #f8fafc;
      }

      .fw-toast {
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 11px;
        line-height: 1.4;
        background-color: #172554 !important;
        background: #172554 !important;
        border: 1px solid #2563eb !important;
        color: #93c5fd;
        transition: all 0.2s ease;
      }

      /* Footer (100% Opaque) */
      .fw-footer {
        padding: 10px 18px;
        background-color: #020617 !important;
        background: #020617 !important;
        border-top: 1px solid #1e293b !important;
        font-size: 10px;
        color: #64748b;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-shrink: 0;
      }
    `;
    shadow.appendChild(styleEl);

    // 1. Status Badge
    const badge = document.createElement("button");
    badge.className = "fw-badge fw-theme-low";
    badge.type = "button";
    badge.setAttribute("aria-label", "Toggle AI Agent Firewall Threat Panel");

    const badgeDot = document.createElement("span");
    badgeDot.className = "fw-badge-dot";

    const badgeIcon = document.createElement("span");
    badgeIcon.className = "fw-badge-icon";
    badgeIcon.textContent = "🛡";

    const badgeInfo = document.createElement("span");
    badgeInfo.className = "fw-badge-info";

    const badgeBrand = document.createElement("span");
    badgeBrand.className = "fw-badge-brand";
    badgeBrand.textContent = "AI Firewall";

    const badgeStatus = document.createElement("span");
    badgeStatus.className = "fw-badge-status";
    badgeStatus.textContent = "LOW RISK • 0/100";

    badgeInfo.appendChild(badgeBrand);
    badgeInfo.appendChild(badgeStatus);

    const badgeChevron = document.createElement("span");
    badgeChevron.className = "fw-badge-chevron";
    badgeChevron.textContent = "▾";

    badge.appendChild(badgeDot);
    badge.appendChild(badgeIcon);
    badge.appendChild(badgeInfo);
    badge.appendChild(badgeChevron);

    // 2. Threat Panel
    const panel = document.createElement("div");
    panel.className = "fw-panel";

    // Panel Header
    const header = document.createElement("div");
    header.className = "fw-panel-header";

    const headerTitleWrap = document.createElement("div");
    headerTitleWrap.className = "fw-header-title-wrap";

    const headerIcon = document.createElement("span");
    headerIcon.className = "fw-header-icon";
    headerIcon.textContent = "🛡";

    const headerTitle = document.createElement("span");
    headerTitle.className = "fw-header-title";
    headerTitle.textContent = "AI Agent Firewall";

    const headerPill = document.createElement("span");
    headerPill.className = "fw-header-pill";
    headerPill.textContent = "Active Protection";

    headerTitleWrap.appendChild(headerIcon);
    headerTitleWrap.appendChild(headerTitle);
    headerTitleWrap.appendChild(headerPill);

    const closeBtn = document.createElement("button");
    closeBtn.className = "fw-close-btn";
    closeBtn.setAttribute("aria-label", "Close firewall threat panel");
    closeBtn.textContent = "✕";

    header.appendChild(headerTitleWrap);
    header.appendChild(closeBtn);

    // Panel Body
    const body = document.createElement("div");
    body.className = "fw-panel-body";

    // Hero Risk Card
    const heroCard = document.createElement("div");
    heroCard.className = "fw-hero-card";

    const heroTop = document.createElement("div");
    heroTop.className = "fw-hero-top";

    const riskBadge = document.createElement("div");
    riskBadge.className = "fw-risk-badge fw-risk-badge-low";
    riskBadge.textContent = "LOW RISK";

    const scoreBox = document.createElement("div");
    scoreBox.className = "fw-score-box";

    const scoreNum = document.createElement("span");
    scoreNum.className = "fw-score-num";
    scoreNum.textContent = "0";

    const scoreDenom = document.createElement("span");
    scoreDenom.className = "fw-score-denom";
    scoreDenom.textContent = "/ 100";

    scoreBox.appendChild(scoreNum);
    scoreBox.appendChild(scoreDenom);

    heroTop.appendChild(riskBadge);
    heroTop.appendChild(scoreBox);

    const actionBox = document.createElement("div");
    actionBox.className = "fw-action-box";

    const actionIcon = document.createElement("span");
    actionIcon.textContent = "🛡";

    const actionText = document.createElement("span");
    actionText.textContent = "Action: Allow";

    actionBox.appendChild(actionIcon);
    actionBox.appendChild(actionText);

    heroCard.appendChild(heroTop);
    heroCard.appendChild(actionBox);

    // Threat Summary
    const summaryBox = document.createElement("div");
    summaryBox.className = "fw-summary-box";
    summaryBox.textContent = "No significant malicious signals detected. Webpage content appears safe for automated assistant processing.";

    // Why flagged / Security Signals Section
    const signalsSection = document.createElement("div");
    const signalsTitle = document.createElement("div");
    signalsTitle.className = "fw-section-title";
    signalsTitle.textContent = "Security Signals Detected";

    const signalsGrid = document.createElement("div");
    signalsGrid.className = "fw-signals-grid";

    signalsSection.appendChild(signalsTitle);
    signalsSection.appendChild(signalsGrid);

    // Mathematical Score Breakdown
    const mathBox = document.createElement("div");
    mathBox.className = "fw-math-box";

    const mathTitle = document.createElement("div");
    mathTitle.className = "fw-section-title";
    mathTitle.textContent = "Risk Score Breakdown";

    // Base meter
    const baseMeter = document.createElement("div");
    baseMeter.className = "fw-meter-row";
    const baseLabelWrap = document.createElement("div");
    baseLabelWrap.className = "fw-meter-label-wrap";
    const baseTitle = document.createElement("span");
    baseTitle.textContent = "Base Evidence (Cap: 65)";
    const baseVal = document.createElement("span");
    baseVal.textContent = "0 / 65";
    baseLabelWrap.appendChild(baseTitle);
    baseLabelWrap.appendChild(baseVal);

    const baseTrack = document.createElement("div");
    baseTrack.className = "fw-meter-bar-track";
    const baseFill = document.createElement("div");
    baseFill.className = "fw-meter-bar-fill";
    baseFill.style.width = "0%";
    baseFill.style.background = "#38bdf8";
    baseTrack.appendChild(baseFill);
    baseMeter.appendChild(baseLabelWrap);
    baseMeter.appendChild(baseTrack);

    // Synergy meter
    const synMeter = document.createElement("div");
    synMeter.className = "fw-meter-row";
    const synLabelWrap = document.createElement("div");
    synLabelWrap.className = "fw-meter-label-wrap";
    const synTitle = document.createElement("span");
    synTitle.textContent = "Contextual Synergy (Cap: 35)";
    const synVal = document.createElement("span");
    synVal.textContent = "0 / 35";
    synLabelWrap.appendChild(synTitle);
    synLabelWrap.appendChild(synVal);

    const synTrack = document.createElement("div");
    synTrack.className = "fw-meter-bar-track";
    const synFill = document.createElement("div");
    synFill.className = "fw-meter-bar-fill";
    synFill.style.width = "0%";
    synFill.style.background = "#818cf8";
    synTrack.appendChild(synFill);
    synMeter.appendChild(synLabelWrap);
    synMeter.appendChild(synTrack);

    // Synergy list
    const synList = document.createElement("div");
    synList.className = "fw-synergies-list";

    mathBox.appendChild(mathTitle);
    mathBox.appendChild(baseMeter);
    mathBox.appendChild(synMeter);
    mathBox.appendChild(synList);

    // Detected Findings Section
    const findingsSection = document.createElement("div");
    findingsSection.className = "fw-findings-wrap";

    const findingsHeader = document.createElement("div");
    findingsHeader.className = "fw-section-title";

    const findingsTitleSpan = document.createElement("span");
    findingsTitleSpan.textContent = "Detected Findings (0)";

    const toggleFindingsBtn = document.createElement("button");
    toggleFindingsBtn.className = "fw-findings-toggle-btn";
    toggleFindingsBtn.textContent = "Collapse";

    findingsHeader.appendChild(findingsTitleSpan);
    findingsHeader.appendChild(toggleFindingsBtn);

    const findingsList = document.createElement("div");
    findingsList.className = "fw-findings-list";

    findingsSection.appendChild(findingsHeader);
    findingsSection.appendChild(findingsList);

    // Actions Section
    const actionsWrap = document.createElement("div");
    actionsWrap.className = "fw-actions-wrap";

    const btnRow = document.createElement("div");
    btnRow.className = "fw-btn-row";

    const sanitizeBtn = document.createElement("button");
    sanitizeBtn.className = "fw-btn fw-btn-primary";
    sanitizeBtn.textContent = "🛡 Sanitize Suspicious Content";

    const rescanBtn = document.createElement("button");
    rescanBtn.className = "fw-btn fw-btn-secondary";
    rescanBtn.textContent = "🔄 Re-scan Page";

    btnRow.appendChild(sanitizeBtn);
    btnRow.appendChild(rescanBtn);

    const toast = document.createElement("div");
    toast.className = "fw-toast";
    toast.style.display = "none";

    actionsWrap.appendChild(btnRow);
    actionsWrap.appendChild(toast);

    // Assemble Body
    body.appendChild(heroCard);
    body.appendChild(summaryBox);
    body.appendChild(signalsSection);
    body.appendChild(mathBox);
    body.appendChild(findingsSection);
    body.appendChild(actionsWrap);

    // Footer
    const footer = document.createElement("div");
    footer.className = "fw-footer";
    const footerLeft = document.createElement("span");
    footerLeft.textContent = "AI Agent Prompt-Injection Firewall • Prototype";
    const footerRight = document.createElement("span");
    footerRight.textContent = "Isolated Shadow DOM";
    footer.appendChild(footerLeft);
    footer.appendChild(footerRight);

    panel.appendChild(header);
    panel.appendChild(body);
    panel.appendChild(footer);

    shadow.appendChild(badge);
    shadow.appendChild(panel);

    // Event Handlers
    function togglePanel() {
      const isVisible = panel.classList.toggle("fw-panel-visible");
      badgeChevron.classList.toggle("open", isVisible);
    }

    badge.addEventListener("click", togglePanel);
    closeBtn.addEventListener("click", () => {
      panel.classList.remove("fw-panel-visible");
      badgeChevron.classList.remove("open");
    });

    let findingsCollapsed = false;
    toggleFindingsBtn.addEventListener("click", () => {
      findingsCollapsed = !findingsCollapsed;
      findingsList.style.display = findingsCollapsed ? "none" : "flex";
      toggleFindingsBtn.textContent = findingsCollapsed ? "Expand" : "Collapse";
    });

    let toastTimer = null;
    function showToast(msg) {
      toast.textContent = msg;
      toast.style.display = "block";
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => {
        toast.style.display = "none";
      }, 5000);
    }

    sanitizeBtn.addEventListener("click", () => {
      showToast("🛡 Quarantining suspicious elements and re-scanning...");
      setTimeout(() => {
        if (typeof sanitizeSuspiciousContent === "function") {
          const result = sanitizeSuspiciousContent();
          if (result && result.quarantinedCount > 0) {
            showToast(`✓ Quarantined ${result.quarantinedCount} element(s). Page re-scanned: Risk score is now ${result.newAssessment.score}/100 (${result.newAssessment.riskLevel}).`);
          } else {
            showToast("ℹ️ No eligible suspicious content detected to sanitize.");
          }
        }
      }, 50);
    });

    rescanBtn.addEventListener("click", () => {
      showToast("🔄 Running complete firewall security scan...");
      setTimeout(() => {
        if (typeof window.AIAgentFirewall?.runAllFirewallScans === "function") {
          window.AIAgentFirewall.runAllFirewallScans();
          showToast("✓ Page re-scanned. Risk assessment updated.");
        }
      }, 50);
    });

    if (document.body) {
      document.body.appendChild(host);
    } else if (document.documentElement) {
      document.documentElement.appendChild(host);
    }

    firewallUICache = {
      host,
      shadow,
      badge,
      badgeDot,
      badgeIcon,
      badgeStatus,
      badgeChevron,
      panel,
      riskBadge,
      scoreNum,
      actionIcon,
      actionText,
      actionBox,
      summaryBox,
      signalsGrid,
      baseVal,
      baseFill,
      synVal,
      synFill,
      synList,
      findingsTitleSpan,
      findingsList,
      showToast,
      togglePanel
    };
  }

  return firewallUICache;
}

function renderOrUpdateFirewallUI(assessment) {
  if (!assessment || typeof document === "undefined") return;

  const ui = ensureFirewallUI();
  if (!ui) return;

  const risk = (assessment.riskLevel || "LOW").toUpperCase();
  const riskLower = risk.toLowerCase();
  const score = Math.round(assessment.score || 0);

  // 1. Update Badge
  ui.badge.className = `fw-badge fw-theme-${riskLower}`;
  ui.badgeStatus.textContent = `${risk} • ${score}/100`;

  let badgeIconChar = "🛡";
  if (risk === "CRITICAL") badgeIconChar = "🛑";
  else if (risk === "HIGH" || risk === "MEDIUM") badgeIconChar = "⚠️";
  ui.badgeIcon.textContent = badgeIconChar;

  // 2. Update Hero Card
  ui.riskBadge.className = `fw-risk-badge fw-risk-badge-${riskLower}`;
  ui.riskBadge.textContent = `${risk} RISK`;
  ui.scoreNum.textContent = String(score);

  if (risk === "CRITICAL") {
    ui.actionIcon.textContent = "🛑";
    ui.actionBox.style.borderLeftColor = "#ef4444";
  } else if (risk === "HIGH") {
    ui.actionIcon.textContent = "⚠️";
    ui.actionBox.style.borderLeftColor = "#f97316";
  } else if (risk === "MEDIUM") {
    ui.actionIcon.textContent = "⚠️";
    ui.actionBox.style.borderLeftColor = "#f59e0b";
  } else {
    ui.actionIcon.textContent = "🛡";
    ui.actionBox.style.borderLeftColor = "#10b981";
  }
  ui.actionText.textContent = assessment.recommendedAction || "Action: Allow";

  // 3. Update Threat Summary
  if (risk === "CRITICAL") {
    ui.summaryBox.textContent = "High-confidence multi-vector threat detected. This page contains combined prompt manipulation directives, concealed elements, and sensitive data requests. Content should be treated as untrusted.";
  } else if (risk === "HIGH") {
    ui.summaryBox.textContent = "Potential prompt-injection threat detected. Webpage contains instructions attempting unauthorized control of AI agent context or sensitive data access.";
  } else if (risk === "MEDIUM") {
    ui.summaryBox.textContent = "Suspicious prompt manipulation directives detected. Review recommended before granting an automated agent permission to process this page.";
  } else {
    ui.summaryBox.textContent = "No significant malicious signals detected. Webpage content appears safe for automated assistant processing.";
  }

  // 4. Update Security Signals ("Why was this page flagged?")
  while (ui.signalsGrid.firstChild) {
    ui.signalsGrid.removeChild(ui.signalsGrid.firstChild);
  }

  const findings = assessment.contributingFindings || [];
  const hiddenSignals = findings.filter(f => f.detector === "hidden-content");
  const obfSignals = findings.filter(f => f.detector === "obfuscation");
  const overrideSignals = findings.filter(f => f.category === "Instruction Override");
  const sensitiveSignals = findings.filter(f => f.category === "Sensitive Data Requests");
  const impersonateSignals = findings.filter(f => f.category === "System/Developer Impersonation");
  const exfilSignals = findings.filter(f => f.category === "External Action / Exfiltration");
  const toolSignals = findings.filter(f => f.category === "Tool/Browser Manipulation");

  const activeSignals = [];
  if (hiddenSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "Hidden Content",
      detail: `${hiddenSignals.length} concealed DOM element(s) (display:none, opacity:0, or zero dimensions)`
    });
  }
  if (obfSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "Obfuscated / Invisible Unicode",
      detail: `${obfSignals.length} text segment(s) containing zero-width or evasion characters`
    });
  }
  if (overrideSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "Instruction Override",
      detail: `${overrideSignals.length} directive(s) attempting to override or ignore prior rules`
    });
  }
  if (sensitiveSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "Sensitive Data Request",
      detail: `${sensitiveSignals.length} command(s) attempting to extract private data or credentials`
    });
  }
  if (impersonateSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "System/Developer Impersonation",
      detail: `${impersonateSignals.length} pattern(s) spoofing privileged system or admin instructions`
    });
  }
  if (exfilSignals.length > 0) {
    activeSignals.push({
      icon: "🛑",
      name: "External Action / Exfiltration",
      detail: `${exfilSignals.length} directive(s) commanding external data transmission`
    });
  }
  if (toolSignals.length > 0) {
    activeSignals.push({
      icon: "⚠️",
      name: "Tool / Browser Manipulation",
      detail: `${toolSignals.length} pattern(s) commanding browser interactions or tool execution`
    });
  }

  if (activeSignals.length === 0) {
    const cleanRow = document.createElement("div");
    cleanRow.className = "fw-signal-row";
    const cleanIcon = document.createElement("span");
    cleanIcon.className = "fw-signal-icon";
    cleanIcon.textContent = "✔";
    const cleanBody = document.createElement("div");
    cleanBody.className = "fw-signal-body";
    const cleanName = document.createElement("span");
    cleanName.className = "fw-signal-name";
    cleanName.textContent = "No Suspicious Signals Found";
    const cleanDetail = document.createElement("span");
    cleanDetail.className = "fw-signal-detail";
    cleanDetail.textContent = "DOM structure, typography, and visible content passed heuristic inspection.";
    cleanBody.appendChild(cleanName);
    cleanBody.appendChild(cleanDetail);
    cleanRow.appendChild(cleanIcon);
    cleanRow.appendChild(cleanBody);
    ui.signalsGrid.appendChild(cleanRow);
  } else {
    activeSignals.forEach(sig => {
      const row = document.createElement("div");
      row.className = "fw-signal-row";

      const iconEl = document.createElement("span");
      iconEl.className = "fw-signal-icon";
      iconEl.textContent = sig.icon;

      const bodyEl = document.createElement("div");
      bodyEl.className = "fw-signal-body";

      const nameEl = document.createElement("span");
      nameEl.className = "fw-signal-name";
      nameEl.textContent = sig.name;

      const detailEl = document.createElement("span");
      detailEl.className = "fw-signal-detail";
      detailEl.textContent = sig.detail;

      bodyEl.appendChild(nameEl);
      bodyEl.appendChild(detailEl);
      row.appendChild(iconEl);
      row.appendChild(bodyEl);
      ui.signalsGrid.appendChild(row);
    });
  }

  // 5. Update Mathematical Score Breakdown
  const baseScore = assessment.baseScore || 0;
  const synBonus = assessment.synergyBonus || 0;

  ui.baseVal.textContent = `${baseScore} / 65`;
  ui.baseFill.style.width = `${Math.min(100, Math.round((baseScore / 65) * 100))}%`;

  ui.synVal.textContent = `${synBonus} / 35`;
  ui.synFill.style.width = `${Math.min(100, Math.round((synBonus / 35) * 100))}%`;

  while (ui.synList.firstChild) {
    ui.synList.removeChild(ui.synList.firstChild);
  }

  const synergies = assessment.appliedSynergies || [];
  let rawSynergySum = 0;
  if (synergies.length > 0) {
    synergies.forEach(s => {
      rawSynergySum += s.bonus;
      const item = document.createElement("div");
      item.className = "fw-synergy-item";

      const pill = document.createElement("span");
      pill.className = "fw-synergy-pill";
      pill.textContent = `+${s.bonus}`;

      const label = document.createElement("span");
      label.textContent = s.name;

      item.appendChild(pill);
      item.appendChild(label);
      ui.synList.appendChild(item);
    });

    if (rawSynergySum >= 35) {
      const capNote = document.createElement("div");
      capNote.className = "fw-cap-note";
      capNote.textContent = "⚡ Synergy bonus capped at 35.";
      ui.synList.appendChild(capNote);
    }
  } else {
    const noSyn = document.createElement("div");
    noSyn.className = "fw-synergy-item";
    noSyn.style.color = "#64748b";
    noSyn.textContent = "No contextual synergies triggered.";
    ui.synList.appendChild(noSyn);
  }

  // 6. Update Detected Findings
  ui.findingsTitleSpan.textContent = `Detected Findings (${findings.length})`;

  while (ui.findingsList.firstChild) {
    ui.findingsList.removeChild(ui.findingsList.firstChild);
  }

  if (findings.length === 0) {
    const emptyNotice = document.createElement("div");
    emptyNotice.style.padding = "8px";
    emptyNotice.style.color = "#64748b";
    emptyNotice.style.fontSize = "11px";
    emptyNotice.textContent = "No threat findings to display.";
    ui.findingsList.appendChild(emptyNotice);
  } else {
    findings.forEach(finding => {
      const card = document.createElement("div");
      card.className = "fw-finding-card";

      const head = document.createElement("div");
      head.className = "fw-finding-head";

      const catSpan = document.createElement("span");
      catSpan.className = "fw-finding-cat";
      catSpan.textContent = finding.category || "Threat Finding";

      const badges = document.createElement("div");
      badges.className = "fw-finding-badges";

      if (finding.detector) {
        const detTag = document.createElement("span");
        detTag.className = "fw-conf-tag";
        detTag.textContent = finding.detector;
        badges.appendChild(detTag);
      }

      if (finding.confidence !== undefined) {
        const confTag = document.createElement("span");
        confTag.className = "fw-conf-tag";
        confTag.textContent = `${Math.round(finding.confidence * 100)}% conf`;
        badges.appendChild(confTag);
      }

      head.appendChild(catSpan);
      head.appendChild(badges);
      card.appendChild(head);

      if (finding.snippet) {
        const snip = document.createElement("div");
        snip.className = "fw-finding-snippet";
        snip.textContent = `"${finding.snippet}"`;
        card.appendChild(snip);
      }

      if (finding.reason) {
        const reasonEl = document.createElement("div");
        reasonEl.className = "fw-finding-reason";
        reasonEl.textContent = finding.reason;
        card.appendChild(reasonEl);
      }

      ui.findingsList.appendChild(card);
    });
  }
}

/**
 * ============================================================================
 * SECTION 11: Sanitization & Quarantine Engine (Step 9)
 * ============================================================================
 */

// In-memory session-only quarantine audit log (never persisted to storage/network)
const sessionQuarantineLog = [];
let isSanitizing = false;

/**
 * Check whether a node is immune to sanitization.
 */
function isElementImmune(element) {
  if (!element || typeof element !== "object") return true;

  // Root and top-level structural containers are never deleted/altered as units
  if (typeof document !== "undefined") {
    if (element === document.documentElement || element === document.body || element === document.head) {
      return true;
    }
  }

  const tagName = (element.tagName || "").toUpperCase();
  if (["HTML", "HEAD", "BODY", "MAIN", "ARTICLE"].includes(tagName)) {
    return true;
  }

  // Firewall's own host and Shadow DOM are strictly immune
  if (element.id === "ai-agent-firewall-host") return true;
  if (typeof element.closest === "function" && element.closest("#ai-agent-firewall-host")) return true;

  // Check if inside shadow root of firewall host
  let cur = element.parentElement || element.parentNode;
  while (cur) {
    if (cur.id === "ai-agent-firewall-host" || (cur.host && cur.host.id === "ai-agent-firewall-host")) {
      return true;
    }
    cur = cur.parentElement || cur.parentNode || cur.host;
  }

  // Idempotency: Already quarantined elements are immune from further modification
  if (typeof element.getAttribute === "function" && element.getAttribute("data-firewall-quarantined") === "true") {
    return true;
  }

  return false;
}

/**
 * Finding-driven sanitization and quarantine engine.
 * Neutralizes verified threats while preserving benign visible content and structural integrity.
 */
function sanitizeSuspiciousContent(customAssessment = null) {
  if (isSanitizing) {
    return { quarantinedCount: 0, quarantinedElements: [], newAssessment: null, quarantineLog: [...sessionQuarantineLog] };
  }
  isSanitizing = true;

  try {
    const assessment = customAssessment ||
      (typeof window !== "undefined" && window.AIAgentFirewall?.riskAssessment) ||
      assessPageRisk();

    if (!assessment || !Array.isArray(assessment.contributingFindings) || assessment.contributingFindings.length === 0) {
      return {
        quarantinedCount: 0,
        quarantinedElements: [],
        newAssessment: assessment,
        quarantineLog: [...sessionQuarantineLog]
      };
    }

    // 1. Group findings by their unique underlying DOM element reference
    const elementToFindings = new Map();
    for (const finding of assessment.contributingFindings) {
      const el = finding.element;
      if (!el || isElementImmune(el)) continue;

      if (!elementToFindings.has(el)) {
        elementToFindings.set(el, []);
      }
      elementToFindings.get(el).push(finding);
    }

    const quarantinedNodes = [];

    // 2. Evaluate each unique candidate element against strict decision rules
    for (const [element, findings] of elementToFindings.entries()) {
      if (isElementImmune(element)) continue;

      // Extract finding signals for this element
      const injectionFindings = findings.filter(f => f.detector === "prompt-injection" && (f.confidence === undefined || f.confidence >= 0.70));
      const hiddenFindings = findings.filter(f => f.detector === "hidden-content");
      const obfuscationFindings = findings.filter(f => f.detector === "obfuscation");

      let hasInjection = injectionFindings.length > 0;
      const isHidden = hiddenFindings.length > 0;
      const isObfuscated = obfuscationFindings.length > 0;

      // RULE 1: Unaccompanied hidden content (e.g. benign navigation, a11y menus, modals) is strictly NOT sanitized
      if (isHidden && !hasInjection && !isObfuscated) {
        continue;
      }

      // RULE 2: Invisible Unicode / zero-width characters are only sanitized if verified adversarial (homoglyphs, control-override, zalgo) OR associated with injection
      if (isObfuscated && !hasInjection) {
        const cleaned = cleanAndNormalizeText(element.textContent || "");
        const hasInjectionInCleaned = cleaned ? testTextForPromptInjection(cleaned).length > 0 : false;
        if (hasInjectionInCleaned) {
          hasInjection = true;
        } else {
          const hasVerifiedAdversarialObf = obfuscationFindings.some(f =>
            ["control-override", "homoglyphs", "combining-marks"].includes(f.category)
          );
          if (!hasVerifiedAdversarialObf) {
            continue; // Strictly preserve legitimate Unicode typography (ZWJ/ZWNJ, emojis, scripts)
          }
        }
      }

      // If no valid threat condition matches, do not touch this element
      if (!hasInjection && !isObfuscated) {
        continue;
      }

      // 3. Apply Safe Neutralization Strategy
      let actionType = "";
      let originalSnippet = findings[0].snippet || "";

      if (isHidden && hasInjection) {
        // Scenario A: Hidden malicious payload. Clear payload text while preserving tag/DOM element to protect layout
        element.textContent = "";
        if (typeof element.innerText !== "undefined") element.innerText = "";
        actionType = "cleared-hidden-payload";
      } else if (isObfuscated && hasInjection) {
        // Scenario B: Obfuscated prompt injection. Defang with safe quarantine sentinel
        const sentinel = "[AI Firewall Quarantined: Malicious obfuscated payload neutralized]";
        element.textContent = sentinel;
        if (typeof element.innerText !== "undefined") element.innerText = sentinel;
        actionType = "neutralized-obfuscated-injection";
      } else if (hasInjection) {
        // Scenario C: Visible prompt injection. Replace hostile text with sentinel tag
        const sentinel = "[AI Firewall Quarantined: Suspicious prompt instruction neutralized]";
        element.textContent = sentinel;
        if (typeof element.innerText !== "undefined") element.innerText = sentinel;
        actionType = "neutralized-visible-injection";
      } else if (isObfuscated) {
        // Scenario D: High-confidence isolated evasion payload without prompt injection
        const cleaned = cleanAndNormalizeText(element.textContent || "");
        element.textContent = cleaned;
        if (typeof element.innerText !== "undefined") element.innerText = cleaned;
        actionType = "stripped-evasion-unicode";
      }

      // 4. Stamp Element with Quarantine Attributes (safe DOM APIs)
      if (typeof element.setAttribute === "function") {
        element.setAttribute("data-firewall-quarantined", "true");
        element.setAttribute("data-firewall-quarantine-type", actionType);
        element.setAttribute("data-firewall-quarantine-time", String(Date.now()));
      }

      // 5. Session-only audit log entry (no persistence across sessions, no telemetry)
      const logEntry = {
        id: `quarantine_${Date.now()}_${sessionQuarantineLog.length + 1}`,
        timestamp: Date.now(),
        tagName: element.tagName || "ELEMENT",
        quarantineType: actionType,
        originalSnippet: originalSnippet,
        findingCategories: findings.map(f => f.category).filter(Boolean)
      };
      sessionQuarantineLog.push(logEntry);
      quarantinedNodes.push(element);
    }

    // 6. Trigger a real Re-Scan and update risk assessment
    let newAssessment = assessment;
    if (typeof runAllFirewallScans === "function") {
      newAssessment = runAllFirewallScans();
    } else if (typeof assessPageRisk === "function") {
      newAssessment = assessPageRisk();
    }

    return {
      quarantinedCount: quarantinedNodes.length,
      quarantinedElements: quarantinedNodes,
      newAssessment: newAssessment,
      quarantineLog: [...sessionQuarantineLog]
    };
  } finally {
    isSanitizing = false;
  }
}

function runAllFirewallScans() {
  runPageScan();
  runHiddenContentScan();
  runObfuscationScan();
  runPromptInjectionScan();
  return runRiskAssessment();
}

// Expose public API methods on window.AIAgentFirewall
if (typeof window !== "undefined") {
  if (!window.AIAgentFirewall) {
    window.AIAgentFirewall = {};
  }
  Object.assign(window.AIAgentFirewall, {
    RISK_CONFIG,
    PROMPT_INJECTION_RULES,
    INVISIBLE_CHARACTERS_MAP,
    BIDI_CONTROL_MAP,
    HOMOGLYPH_MAP,
    normalizeWhitespace,
    normalizeForPromptMatching,
    cleanAndNormalizeText,
    checkHiddenTechnique,
    detectHiddenContent,
    runHiddenContentScan,
    analyzeTextForObfuscation,
    detectObfuscatedText,
    runObfuscationScan,
    testTextForPromptInjection,
    detectPromptInjection,
    runPromptInjectionScan,
    calculateFindingEvidence,
    evaluateSynergies,
    classifyRiskLevel,
    getTargetKey,
    assessPageRisk,
    assessRisk: assessPageRisk,
    runRiskAssessment,
    runAllFirewallScans,
    isElementImmune,
    sanitizeSuspiciousContent,
    sanitizePage: sanitizeSuspiciousContent,
    quarantineLog: sessionQuarantineLog,
    getQuarantineLog: () => sessionQuarantineLog
  });
}

if (typeof document !== "undefined" && document.readyState) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", runAllFirewallScans);
  } else {
    runAllFirewallScans();
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = typeof window !== "undefined" ? window.AIAgentFirewall : {};
}
