// Core behavior for checkpass UI


(() => {
  const passwordInput = document.getElementById("password");
  const strengthBar = document.getElementById("strengthBar");
  const feedback = document.getElementById("feedback");
  const breachResult = document.getElementById("breachResult");
  const strengthText = document.getElementById("strengthText");
//   const segments = document.querySelectorAll(".strength-seg");
//   const strengthBadge = document.getElementById("strengthBadge");
  const toggleBtn = document.getElementById("toggleBtn");
  const copyBtn = document.getElementById("copyBtn");

  let breachTimer = null;
  let lastCheckToken = 0;

  // toggle visibility
  toggleBtn.addEventListener("click", () => {
    const isText = passwordInput.type === "text";
    passwordInput.type = isText ? "password" : "text";
    toggleBtn.setAttribute("aria-pressed", String(!isText));
    toggleBtn.title = isText ? "Show password" : "Hide password";
  });

  // copy with fallback
  copyBtn.addEventListener("click", async () => {
    const text = passwordInput.value;
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      copyBtn.title = "Copied!";
      setTimeout(() => (copyBtn.title = "Copy password"), 1400);
    } catch {
      // fallback: select + execCommand
      try {
        passwordInput.select();
        document.execCommand("copy");
        copyBtn.title = "Copied!";
      } catch {
        copyBtn.title = "Copy failed";
      } finally {
        setTimeout(() => (copyBtn.title = "Copy password"), 1400);
        window.getSelection().removeAllRanges();
      }
    }
  });

passwordInput.addEventListener("input", async () => {
    const pwd = passwordInput.value;

    // Password strength analysis using zxcvbn
    const result = zxcvbn(pwd);
    const score = result.score;

    // Update strength bar
    strengthBar.className = 'strength';
    if (score === 0 || score === 1) strengthBar.classList.add("weak");
    else if (score === 2 || score === 3) strengthBar.classList.add("medium");
    else if (score === 4) strengthBar.classList.add("strong");

    const labels = ["Very weak","Weak","Fair","Good","Strong"];
    strengthText.querySelector("strong").textContent = labels[score] || "—";

    feedback.textContent = result.feedback.warning || (result.feedback.suggestions.length ? result.feedback.suggestions.join(' ') : "Looks good!");
    // debounce breach checks
    if (breachTimer) clearTimeout(breachTimer);
    breachResult.textContent = "";
    breachResult.className = "";

    if (pwd.length >= 6) {
      const checkToken = ++lastCheckToken;
      breachTimer = setTimeout(async () => {
        // show spinner
        breachResult.innerHTML = 'Checking<span class="spinner" aria-hidden="true"></span>';
        try {
          const isBreached = await checkPasswordBreach(pwd);
          if (checkToken !== lastCheckToken) return; // ignore outdated
          if (isBreached) {
            breachResult.textContent = "⚠️ This password has appeared in a known data breach!";
            breachResult.className = "breached";
          } else {
            breachResult.textContent = "✅ Password not found in breach database.";
            breachResult.className = "ok";
          }
        } catch (e) {
          if (checkToken !== lastCheckToken) return;
          breachResult.textContent = "⚠️ Unable to check breaches right now.";
          breachResult.className = "";
        }
      }, 550);
    }
  });

  // Uses k-anonymity API (Have I Been Pwned)
  async function checkPasswordBreach(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    const prefix = hashHex.slice(0, 5);
    const suffix = hashHex.slice(5);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { cache: "no-store", signal: controller.signal });
    clearTimeout(timeout);

    if (!resp.ok) throw new Error("Network error");
    const text = await resp.text();
    // Check suffix presence
    const found = text.split("\n").some(line => {
      const [hashPart] = line.split(":");
      return hashPart && hashPart.trim().toUpperCase() === suffix;
    });
    return found;
  }
})();