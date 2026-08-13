/* ================================================================
   Password Security Analyzer & Risk Assessment Tool
   All analysis runs entirely client-side. No network calls.
   ================================================================ */

/* ---------- Static local datasets (no APIs, no downloads) ---------- */

const COMMON_PASSWORDS = [
  "password", "123456", "123456789", "qwerty", "12345678", "111111",
  "1234567", "12345", "1234567890", "letmein", "welcome", "admin",
  "abc123", "password123", "iloveyou", "monkey", "dragon", "sunshine",
  "master", "football", "shadow", "superman", "trustno1", "hello",
  "login", "princess", "qwertyuiop", "starwars", "freedom", "whatever",
  "passw0rd", "baseball", "1q2w3e4r", "michael", "jennifer", "hunter2"
];

const LEET_MAP = { "@": "a", "4": "a", "0": "o", "1": "i", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t" };

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

const WORD_LIST = [
  "river", "moon", "cactus", "laptop", "forest", "ember", "granite", "willow",
  "comet", "harbor", "meadow", "signal", "quartz", "lantern", "canyon", "otter",
  "voyage", "cipher", "prairie", "thistle", "beacon", "orbit", "marble", "falcon",
  "glacier", "ember", "cobalt", "juniper", "nebula", "ridge", "tundra", "violet",
  "anchor", "briar", "cinder", "delta", "ember", "fjord", "gravel", "hollow"
];

/* ---------- Character pool + entropy ---------- */

function getCharPool(password) {
  const pool = { lower: 0, upper: 0, digits: 0, symbols: 0 };
  if (/[a-z]/.test(password)) pool.lower = 26;
  if (/[A-Z]/.test(password)) pool.upper = 26;
  if (/[0-9]/.test(password)) pool.digits = 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool.symbols = 32;
  pool.total = pool.lower + pool.upper + pool.digits + pool.symbols;
  return pool;
}

function calculateEntropy(password) {
  if (!password) return { bits: 0, pool: getCharPool("") };
  const pool = getCharPool(password);
  const bits = pool.total > 0 ? password.length * Math.log2(pool.total) : 0;
  return { bits: Math.round(bits * 10) / 10, pool };
}

/* ---------- Leetspeak normalization (for common-password matching) ---------- */

function normalizeLeet(password) {
  return password
    .toLowerCase()
    .split("")
    .map(ch => LEET_MAP[ch] || ch)
    .join("");
}

/* ---------- Common password detection (with substitution awareness) ---------- */

function checkCommonPassword(password) {
  if (!password) return { isCommon: false, matched: null, substituted: false };
  const lower = password.toLowerCase();
  const normalized = normalizeLeet(password);

  if (COMMON_PASSWORDS.includes(lower)) {
    return { isCommon: true, matched: lower, substituted: false };
  }
  if (COMMON_PASSWORDS.includes(normalized)) {
    return { isCommon: true, matched: normalized, substituted: true };
  }
  // Strip trailing digits (e.g. "password2024") and check the stem
  const stem = lower.replace(/[0-9]+$/, "");
  if (stem.length >= 4 && COMMON_PASSWORDS.includes(stem)) {
    return { isCommon: true, matched: stem, substituted: false };
  }
  const normalizedStem = normalized.replace(/[0-9]+$/, "");
  if (normalizedStem.length >= 4 && COMMON_PASSWORDS.includes(normalizedStem)) {
    return { isCommon: true, matched: normalizedStem, substituted: true };
  }
  return { isCommon: false, matched: null, substituted: false };
}

/* ---------- Pattern / predictability detection ---------- */

function hasSequentialRun(str, minRun = 4) {
  // Detects ascending or descending runs of consecutive chars, e.g. abcd, 4321
  for (let i = 0; i <= str.length - minRun; i++) {
    let asc = true, desc = true;
    for (let j = 1; j < minRun; j++) {
      const diff = str.charCodeAt(i + j) - str.charCodeAt(i + j - 1);
      if (diff !== 1) asc = false;
      if (diff !== -1) desc = false;
    }
    if (asc || desc) return true;
  }
  return false;
}

function hasKeyboardRun(str, minRun = 4) {
  const lower = str.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let i = 0; i <= row.length - minRun; i++) {
      const chunk = row.slice(i, i + minRun);
      const reversed = chunk.split("").reverse().join("");
      if (lower.includes(chunk) || lower.includes(reversed)) return true;
    }
  }
  return false;
}

function hasRepeatedChar(str, minRun = 3) {
  return new RegExp(`(.)\\1{${minRun - 1},}`).test(str);
}

function hasRepeatedWord(str) {
  // e.g. "sunsun", "loveLOVE"
  const lower = str.toLowerCase();
  for (let len = 2; len <= Math.floor(lower.length / 2); len++) {
    for (let i = 0; i <= lower.length - len * 2; i++) {
      if (lower.slice(i, i + len) === lower.slice(i + len, i + len * 2)) return true;
    }
  }
  return false;
}

function hasYearPattern(str) {
  return /(19[0-9]{2}|20[0-9]{2})/.test(str);
}

function detectPatterns(password) {
  if (!password) return [];
  const results = [];

  if (hasSequentialRun(password)) results.push({ label: "Sequential characters (e.g. abcd, 4321)", bad: true });
  if (hasKeyboardRun(password)) results.push({ label: "Keyboard-adjacent sequence (e.g. qwerty, asdf)", bad: true });
  if (hasRepeatedChar(password)) results.push({ label: "Repeated character run (e.g. aaaa, 1111)", bad: true });
  if (hasRepeatedWord(password)) results.push({ label: "Repeated word or chunk (e.g. sunsun)", bad: true });
  if (hasYearPattern(password)) results.push({ label: "Contains a recognizable year", bad: true });

  const common = checkCommonPassword(password);
  if (common.isCommon) {
    results.push({
      label: common.substituted
        ? `Matches common password "${common.matched}" via character substitution`
        : `Matches known common password "${common.matched}"`,
      bad: true
    });
  }

  if (results.length === 0) {
    results.push({ label: "No obvious predictable pattern detected", bad: false });
  }
  return results;
}

/* ---------- Security score (deterministic, transparent) ---------- */

function calculateScore(password) {
  if (!password) return 0;
  let score = 100;
  const { bits } = calculateEntropy(password);
  const pool = getCharPool(password);
  const patterns = detectPatterns(password);
  const common = checkCommonPassword(password);

  // Length
  if (password.length < 8) score -= 35;
  else if (password.length < 12) score -= 15;
  else if (password.length >= 16) score += 5;

  // Character diversity
  const categories = [pool.lower, pool.upper, pool.digits, pool.symbols].filter(v => v > 0).length;
  if (categories <= 1) score -= 25;
  else if (categories === 2) score -= 12;
  else if (categories === 4) score += 5;

  // Entropy
  if (bits < 28) score -= 20;
  else if (bits < 36) score -= 10;
  else if (bits >= 60) score += 10;
  else if (bits >= 80) score += 15;

  // Common password / substitutions
  if (common.isCommon) score -= 40;

  // Pattern penalties (excluding the "no pattern" placeholder)
  const badPatterns = patterns.filter(p => p.bad);
  score -= badPatterns.length * 10;

  return Math.max(0, Math.min(100, Math.round(score)));
}

function scoreToLevel(score) {
  if (score < 20) return "Very Weak";
  if (score < 40) return "Weak";
  if (score < 60) return "Moderate";
  if (score < 80) return "Strong";
  return "Very Strong";
}

function levelClass(level) {
  if (level === "Very Weak" || level === "Weak") return "level-weak";
  if (level === "Moderate") return "level-moderate";
  return "level-strong";
}

/* ---------- Brute-force resistance estimate ---------- */

function estimateBruteForce(password) {
  if (!password) return { category: "—", combos: "" };
  const { bits } = calculateEntropy(password);
  const combos = Math.pow(2, bits);

  let category;
  if (bits < 28) category = "Low resistance";
  else if (bits < 50) category = "Moderate resistance";
  else if (bits < 70) category = "High resistance";
  else category = "Very high resistance";

  let combosText;
  if (combos < 1e6) combosText = `≈ ${Math.round(combos).toLocaleString()} possible combinations`;
  else combosText = `≈ 10^${Math.round(Math.log10(combos))} possible combinations`;

  return { category, combos: combosText };
}

/* ---------- Recommendations ---------- */

function generateRecommendations(password) {
  if (!password) return [];
  const recs = [];
  const pool = getCharPool(password);
  const common = checkCommonPassword(password);
  const patterns = detectPatterns(password).filter(p => p.bad);

  if (password.length < 12) recs.push("Increase the password length to at least 12–14 characters.");
  if (pool.upper === 0) recs.push("Add uppercase letters.");
  if (pool.lower === 0) recs.push("Add lowercase letters.");
  if (pool.digits === 0) recs.push("Add numbers.");
  if (pool.symbols === 0) recs.push("Consider adding special characters.");
  if (common.isCommon) recs.push("Avoid commonly used passwords, even with substitutions like @ for a.");
  if (patterns.length > 0) recs.push("Avoid predictable sequences such as 123456, qwerty, or repeated characters.");

  if (recs.length === 0) recs.push("__GOOD__Good password structure — no major weaknesses detected.");
  return recs;
}

/* ================================================================
   UI: Analyzer panel
   ================================================================ */

const pwInput = document.getElementById("pwInput");
const toggleVisibility = document.getElementById("toggleVisibility");
const clearBtn = document.getElementById("clearBtn");
const charCount = document.getElementById("charCount");
const lengthWarning = document.getElementById("lengthWarning");

const gaugeFill = document.getElementById("gaugeFill");
const scoreNum = document.getElementById("scoreNum");
const levelBadge = document.getElementById("levelBadge");
const entropyVal = document.getElementById("entropyVal");
const lengthVal = document.getElementById("lengthVal");
const poolVal = document.getElementById("poolVal");

const charChecklist = document.getElementById("charChecklist");
const patternList = document.getElementById("patternList");
const commonResult = document.getElementById("commonResult");
const bfCategory = document.getElementById("bfCategory");
const bfCombos = document.getElementById("bfCombos");
const recsList = document.getElementById("recsList");
const calcExample = document.getElementById("calcExample");

const GAUGE_CIRC = 251; // path length approximation for the arc

function analyzePassword(password) {
  const score = calculateScore(password);
  const level = scoreToLevel(score);
  const { bits, pool } = calculateEntropy(password);

  // Gauge
  const offset = GAUGE_CIRC - (GAUGE_CIRC * score) / 100;
  gaugeFill.style.strokeDashoffset = password ? offset : GAUGE_CIRC;
  gaugeFill.style.stroke = score < 40 ? "var(--red)" : score < 70 ? "var(--amber)" : "var(--green)";
  scoreNum.textContent = password ? score : 0;

  levelBadge.textContent = password ? level : "Very Weak";
  levelBadge.className = "level-badge " + levelClass(password ? level : "Very Weak");

  entropyVal.textContent = `${bits} bits`;
  lengthVal.textContent = `${password.length} chars`;
  poolVal.textContent = pool.total;

  // Character count / warning
  charCount.textContent = `${password.length} characters`;
  lengthWarning.textContent = password.length > 128 ? "Unusually long input" : "";

  // Checklist
  const checks = [
    pool.lower > 0,
    pool.upper > 0,
    pool.digits > 0,
    pool.symbols > 0,
    password.length >= 12
  ];
  [...charChecklist.children].forEach((el, i) => {
    const ok = checks[i];
    el.dataset.ok = ok;
    if (password.length > 0) el.classList.add("touched");
    el.querySelector(".chk-icon").textContent = ok ? "✓" : "–";
  });

  // Patterns
  patternList.innerHTML = "";
  if (!password) {
    patternList.innerHTML = '<p class="muted">Start typing to see results.</p>';
  } else {
    detectPatterns(password).forEach(p => {
      const div = document.createElement("div");
      div.className = "pattern-item" + (p.bad ? "" : " ok");
      div.textContent = (p.bad ? "⚠ " : "✓ ") + p.label;
      patternList.appendChild(div);
    });
  }

  // Common password
  if (!password) {
    commonResult.textContent = "No password entered yet.";
    commonResult.className = "status-line muted";
  } else {
    const common = checkCommonPassword(password);
    if (common.isCommon) {
      commonResult.textContent = "⚠ Common Password Detected";
      commonResult.className = "status-line danger";
    } else {
      commonResult.textContent = "✓ No common password match detected";
      commonResult.className = "status-line safe";
    }
  }

  // Brute force
  const bf = estimateBruteForce(password);
  bfCategory.textContent = bf.category;
  bfCombos.textContent = bf.combos;

  // Recommendations
  recsList.innerHTML = "";
  const recs = generateRecommendations(password);
  if (recs.length === 0) {
    recsList.innerHTML = '<li class="muted">Recommendations will appear here.</li>';
  } else {
    recs.forEach(r => {
      const li = document.createElement("li");
      if (r.startsWith("__GOOD__")) {
        li.textContent = "✓ " + r.replace("__GOOD__", "");
        li.className = "good";
      } else {
        li.textContent = r;
      }
      recsList.appendChild(li);
    });
  }

  // Calculation example
  if (password) {
    calcExample.textContent =
      `length ${password.length} × log2(${pool.total}) ≈ ${bits} bits ` +
      `(lower ${pool.lower}, upper ${pool.upper}, digits ${pool.digits}, symbols ${pool.symbols})`;
  } else {
    calcExample.textContent = "Type a password above to see the live calculation.";
  }

  if (password) saveHistoryEntry(score, bits, password.length, level);
}

pwInput.addEventListener("input", () => analyzePassword(pwInput.value));

toggleVisibility.addEventListener("click", () => {
  pwInput.type = pwInput.type === "password" ? "text" : "password";
});

clearBtn.addEventListener("click", () => {
  pwInput.value = "";
  pwInput.focus();
  analyzePassword("");
});

document.getElementById("calcToggle").addEventListener("click", (e) => {
  const btn = e.currentTarget;
  const body = document.getElementById("calcBody");
  const expanded = btn.getAttribute("aria-expanded") === "true";
  btn.setAttribute("aria-expanded", String(!expanded));
  body.style.maxHeight = expanded ? "0" : body.scrollHeight + "px";
});

/* ---------- Analysis history (stats only, never the password) ---------- */

const HISTORY_KEY = "psa_history_v1";
const historyList = document.getElementById("historyList");

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

function saveHistoryEntry(score, bits, length, level) {
  const history = loadHistory();
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  history.unshift({ score, bits, length, level, time });
  localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 8)));
  renderHistory();
}

function renderHistory() {
  const history = loadHistory();
  if (history.length === 0) {
    historyList.innerHTML = '<p class="muted">No history yet.</p>';
    return;
  }
  historyList.innerHTML = history.map(h =>
    `<div class="history-row"><span>${h.time}</span><span>Score ${h.score} · ${h.bits}b · ${h.level}</span></div>`
  ).join("");
}

document.getElementById("clearHistoryBtn").addEventListener("click", () => {
  localStorage.removeItem(HISTORY_KEY);
  renderHistory();
});

renderHistory();
analyzePassword("");

/* ================================================================
   Tabs
   ================================================================ */

document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
  });
});

/* ================================================================
   Secure password generator
   ================================================================ */

const genLength = document.getElementById("genLength");
const genLengthLabel = document.getElementById("genLengthLabel");
genLength.addEventListener("input", () => genLengthLabel.textContent = genLength.value);

function generatePassword(length, useUpper, useLower, useNumbers, useSymbols) {
  const sets = [];
  if (useLower) sets.push("abcdefghijklmnopqrstuvwxyz");
  if (useUpper) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  if (useNumbers) sets.push("0123456789");
  if (useSymbols) sets.push("!@#$%^&*()_+-=[]{}");
  if (sets.length === 0) return "";

  const allChars = sets.join("");
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);

  let result = "";
  // Guarantee at least one char from each selected set, then fill randomly
  const guaranteed = sets.map(set => set[crypto.getRandomValues(new Uint32Array(1))[0] % set.length]);
  for (let i = 0; i < length; i++) {
    if (i < guaranteed.length) {
      result += guaranteed[i];
    } else {
      result += allChars[randomValues[i] % allChars.length];
    }
  }
  // Shuffle using Fisher-Yates with crypto randomness
  const arr = result.split("");
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join("");
}

document.getElementById("genBtn").addEventListener("click", () => {
  const length = parseInt(genLength.value, 10);
  const upper = document.getElementById("genUpper").checked;
  const lower = document.getElementById("genLower").checked;
  const numbers = document.getElementById("genNumbers").checked;
  const symbols = document.getElementById("genSymbols").checked;

  const pwd = generatePassword(length, upper, lower, numbers, symbols);
  const output = document.getElementById("genOutput");
  const resultBlock = document.getElementById("genResult");

  if (!pwd) {
    output.value = "";
    resultBlock.hidden = true;
    return;
  }

  output.value = pwd;
  const score = calculateScore(pwd);
  const { bits } = calculateEntropy(pwd);
  document.getElementById("genScore").textContent = score + "/100";
  document.getElementById("genEntropy").textContent = bits + " bits";
  document.getElementById("genLevel").textContent = scoreToLevel(score);
  resultBlock.hidden = false;
});

document.getElementById("genCopyBtn").addEventListener("click", () => {
  const output = document.getElementById("genOutput");
  if (output.value) navigator.clipboard.writeText(output.value);
});

document.getElementById("genAnalyzeBtn").addEventListener("click", () => {
  const pwd = document.getElementById("genOutput").value;
  if (!pwd) return;
  document.querySelector('.tab[data-tab="analyzer"]').click();
  pwInput.value = pwd;
  pwInput.type = "text";
  analyzePassword(pwd);
});

/* ================================================================
   Passphrase generator
   ================================================================ */

const wordCount = document.getElementById("wordCount");
const wordCountLabel = document.getElementById("wordCountLabel");
wordCount.addEventListener("input", () => wordCountLabel.textContent = wordCount.value);

function generatePassphrase(count, separator) {
  const words = [];
  const randoms = new Uint32Array(count);
  crypto.getRandomValues(randoms);
  for (let i = 0; i < count; i++) {
    words.push(WORD_LIST[randoms[i] % WORD_LIST.length]);
  }
  return words.join(separator);
}

document.getElementById("passphraseBtn").addEventListener("click", () => {
  const count = parseInt(wordCount.value, 10);
  const sep = document.getElementById("separatorSelect").value;
  const phrase = generatePassphrase(count, sep);

  document.getElementById("passphraseOutput").value = phrase;
  const score = calculateScore(phrase);
  const { bits } = calculateEntropy(phrase);
  document.getElementById("passphraseScore").textContent = score + "/100";
  document.getElementById("passphraseEntropy").textContent = bits + " bits";
  document.getElementById("passphraseLevel").textContent = scoreToLevel(score);
  document.getElementById("passphraseResult").hidden = false;
});

document.getElementById("passphraseCopyBtn").addEventListener("click", () => {
  const output = document.getElementById("passphraseOutput");
  if (output.value) navigator.clipboard.writeText(output.value);
});

/* ================================================================
   Compare two passwords
   ================================================================ */

document.getElementById("compareBtn").addEventListener("click", () => {
  const a = document.getElementById("pwA").value;
  const b = document.getElementById("pwB").value;
  if (!a && !b) return;

  const scoreA = calculateScore(a), scoreB = calculateScore(b);
  const entA = calculateEntropy(a), entB = calculateEntropy(b);
  const patA = detectPatterns(a).filter(p => p.bad).length;
  const patB = detectPatterns(b).filter(p => p.bad).length;

  document.getElementById("cmpLenA").textContent = a.length;
  document.getElementById("cmpLenB").textContent = b.length;
  document.getElementById("cmpEntA").textContent = entA.bits + " bits";
  document.getElementById("cmpEntB").textContent = entB.bits + " bits";
  document.getElementById("cmpScoreA").textContent = scoreA + "/100";
  document.getElementById("cmpScoreB").textContent = scoreB + "/100";
  document.getElementById("cmpPatA").textContent = patA + " issue(s)";
  document.getElementById("cmpPatB").textContent = patB + " issue(s)";
  document.getElementById("cmpLevelA").textContent = scoreToLevel(scoreA);
  document.getElementById("cmpLevelB").textContent = scoreToLevel(scoreB);

  document.getElementById("compareTable").hidden = false;

  const verdict = document.getElementById("compareVerdict");
  verdict.hidden = false;
  if (scoreA === scoreB) {
    verdict.textContent = "Both passwords have comparable overall security.";
    verdict.className = "status-line muted";
  } else {
    const winner = scoreA > scoreB ? "Password A" : "Password B";
    verdict.textContent = `${winner} has stronger overall security characteristics.`;
    verdict.className = "status-line safe";
  }
});
