Please read `fix.md` and update the Ollama system prompt in `app.py` according to the requirements specified in that document.

**Tasks:**
1. Read and understand all requirements in `fix.md`
2. Locate the current Ollama system prompt in `app.py` (likely in the `analyze_with_ollama()` function)
3. Rewrite the system prompt to meet all the quality standards described in `fix.md`
4. Ensure the new prompt instructs Ollama to:
   - Provide technical explanations for every CVE mentioned
   - Include specific commands for verification
   - Build attack chains from actual scan results
   - Avoid generic advice like "update software" without details
   - Follow the exact output structure specified in fix.md

**After updating:**
1. Show me the complete updated system prompt section
2. Run `/review` to self-check if the implementation meets the fix.md requirements
3. Specifically verify in your review:
   - Does the prompt enforce evidence-based CVE usage?
   - Does it prohibit generic recommendations?
   - Does it require specific verification commands?
   - Will it produce the quality metrics described in fix.md?

**Finally:**
1. Commit the changes with message: "Improve Ollama analysis quality - evidence-based vulnerability reporting"
2. Push to the repository

Please proceed step by step and show your reasoning at each stage.
