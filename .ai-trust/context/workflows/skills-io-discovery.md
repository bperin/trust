# Workflow: skills.io Auto-Discovery & Triggering

## When

When an AI agent (Architect or Implementer) encounters an unfamiliar domain, technical requirement, or specialized tool integration (e.g., Web3 deployment, BigQuery optimization, Quant trading models) during planning or implementation.

## How It Works

1. **Query Intent Matching:** The agent analyzes the active task requirements and extracts capability keywords (e.g., `bigquery`, `solana`, `stripe-billing`).
2. **Registry Lookup (`skills.io` / local skills directory):** The agent queries the `skills.io` registry API or checks the local master skills directory (`~/.agents/skills/`).
3. **Auto-Download & Activation:** If a matching skill is found but not installed, the CLI automatically fetches and activates it:
   ```bash
   npx project-context skill install <skill-name>
   ```
4. **Execution Guidance:** The activated skill injects specialized instructions into the agent's context window, ensuring expert-level execution without manual user intervention.

## Integration Hook (`bin/cli.js` extension)

```javascript
// Example conceptual auto-discovery helper
async function discoverAndLoadSkill(keyword) {
  const response = await fetch(`https://skills.io/api/v1/search?q=${keyword}`);
  const skill = await response.json();
  if (skill) {
    console.log(`Auto-discovered skill: ${skill.name}. Installing...`);
    // install skill into ~/.agents/skills/
  }
}
```
