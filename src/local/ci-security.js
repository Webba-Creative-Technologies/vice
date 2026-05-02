// ──────────────────────────────────────────────
// VICE LOCAL — CI/CD Workflow Security
// Audits .github/workflows/*.yml for common misconfigurations:
// unpinned actions, dangerous pull_request_target patterns, overly broad
// permissions, and secrets being echoed to logs.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

function getLine(content, position) {
  return content.substring(0, position).split('\n').length;
}

export async function auditCiSecurity(projectPath, spinner) {
  const workflowsDir = path.join(projectPath, '.github', 'workflows');
  if (!fs.existsSync(workflowsDir)) {
    addFinding('INFO', 'CI/CD Security', 'No GitHub Actions workflows found', '', '');
    return;
  }

  spinner.text = 'Auditing GitHub Actions workflows...';

  const files = (await fs.promises.readdir(workflowsDir)).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'));
  if (files.length === 0) {
    addFinding('INFO', 'CI/CD Security', 'Workflows directory is empty', '', '');
    return;
  }

  let totalIssues = 0;

  for (const file of files) {
    const filePath = path.join(workflowsDir, file);
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);

    // 1. Unpinned third-party actions (not pinned to a 40-char SHA).
    const usesRegex = /^[ \t]*(?:-\s*)?uses:\s*([^\s@#]+)@([^\s#]+)/gm;
    let m;
    while ((m = usesRegex.exec(content)) !== null) {
      const action = m[1];
      const ref = m[2];
      // Skip local actions (./path) and Docker image refs (docker://)
      if (action.startsWith('./') || action.startsWith('docker://')) continue;
      // SHA pin check
      if (!/^[a-f0-9]{40}$/i.test(ref)) {
        const line = getLine(content, m.index);
        addFinding(
          'MEDIUM',
          'CI/CD Security',
          `Unpinned action ${action}@${ref} in ${rel}:${line}`,
          `Action is referenced by tag/branch (${ref}) instead of a commit SHA. A maintainer (or attacker who compromises the repo) can move the tag to malicious code.`,
          `Pin to a full 40-char SHA: uses: ${action}@<sha>  # ${ref}`,
          { file: rel, line },
          'medium'
        );
        totalIssues++;
      }
    }

    // 2. pull_request_target combined with checkout of the PR head
    if (/^[ \t]*-?\s*pull_request_target\s*:?$/m.test(content) || /\bon:\s*\[?\s*[^\]]*pull_request_target/m.test(content)) {
      const checkoutPrHead = /uses:\s*actions\/checkout[^\n]*\n[\s\S]{0,500}?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/i;
      if (checkoutPrHead.test(content)) {
        addFinding(
          'CRITICAL',
          'CI/CD Security',
          `pull_request_target with PR-head checkout in ${rel}`,
          `Combining pull_request_target (which has secrets access) with checking out the PR head allows untrusted PR code to run with secrets. Classic supply-chain attack vector.`,
          `Use the pull_request event instead, or do not check out PR code from a pull_request_target workflow.`,
          { file: rel },
          'high'
        );
        totalIssues++;
      } else {
        addFinding(
          'MEDIUM',
          'CI/CD Security',
          `pull_request_target trigger in ${rel}`,
          `pull_request_target runs with secrets and the base branch's permissions. Verify no untrusted PR code is executed.`,
          `Audit each step in this workflow to ensure no PR-controlled input flows into shell commands or builds.`,
          { file: rel },
          'medium'
        );
        totalIssues++;
      }
    }

    // 3. Overly broad permissions
    const writeAllMatch = content.match(/^\s*permissions:\s*write-all\s*$/m);
    if (writeAllMatch) {
      const line = getLine(content, content.indexOf(writeAllMatch[0]));
      addFinding(
        'MEDIUM',
        'CI/CD Security',
        `permissions: write-all in ${rel}:${line}`,
        `Workflow has write access to every API surface. Principle of least privilege not applied.`,
        `Specify only the permissions you need, e.g.\n  permissions:\n    contents: read\n    pull-requests: write`,
        { file: rel, line },
        'high'
      );
      totalIssues++;
    }

    // 4. Echoing secrets to logs
    const echoSecretRegex = /\b(?:echo|printf|cat\s+<<|>>\s*\$GITHUB_OUTPUT)[^\n]*\$\{\{\s*secrets\./gi;
    while ((m = echoSecretRegex.exec(content)) !== null) {
      const line = getLine(content, m.index);
      addFinding(
        'CRITICAL',
        'CI/CD Security',
        `Secret echoed to log in ${rel}:${line}`,
        `Echoing a value that came from secrets exposes it in the workflow log. GitHub's masking is best-effort and can be bypassed.`,
        `Never echo secrets. Pass them through env: and reference $VAR inside the script. If you need to write to a file, redirect without echoing first.`,
        { file: rel, line },
        'high'
      );
      totalIssues++;
    }

    // 5. Workflows triggered by issue_comment / discussion that run untrusted scripts
    if (/on:\s*\n[\s\S]{0,200}?issue_comment/m.test(content) && /run:[\s\S]{0,500}?\$\{\{\s*github\.event\.comment\.body/i.test(content)) {
      addFinding(
        'HIGH',
        'CI/CD Security',
        `Untrusted comment body interpolated into shell in ${rel}`,
        `github.event.comment.body is attacker-controlled. Interpolating it into a shell command enables arbitrary code execution as the workflow.`,
        `Move the comment body into env: and reference "$BODY" in shell. Or use github-script with proper escaping.`,
        { file: rel },
        'high'
      );
      totalIssues++;
    }
  }

  // ── GitLab CI ──
  const gitlabCi = path.join(projectPath, '.gitlab-ci.yml');
  if (fs.existsSync(gitlabCi)) {
    spinner.text = 'Auditing .gitlab-ci.yml...';
    let content;
    try { content = await fs.promises.readFile(gitlabCi, 'utf-8'); } catch { content = null; }
    if (content) {
      const rel = '.gitlab-ci.yml';

      // image: foo:latest (or no tag = latest)
      const imageRegex = /^[ \t]*image:\s*([^\s#]+)\s*$/gim;
      let m;
      while ((m = imageRegex.exec(content)) !== null) {
        const img = m[1].trim().replace(/['"]/g, '');
        const tag = img.split(':')[1];
        if (!tag || tag === 'latest') {
          const line = getLine(content, m.index);
          addFinding('LOW', 'CI/CD Security', `GitLab CI image without explicit tag in ${rel}:${line}`,
            `${m[0].trim()}\nPipeline image is not version-pinned, builds are non-reproducible.`,
            `Pin to a specific version: image: ${img.split(':')[0]}:1.2.3`,
            { file: rel, line }, 'high');
          totalIssues++;
        }
      }

      // Hardcoded secret-like top-level variables
      const varSecretRegex = /^[ \t]+(\w*(?:SECRET|PASSWORD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)\w*)\s*:\s*["']?([^"'\n#$]+)["']?/gim;
      while ((m = varSecretRegex.exec(content)) !== null) {
        const value = m[2].trim();
        if (!value || value.length < 6) continue;
        if (/your_|example|placeholder|xxx|changeme|\$/i.test(value)) continue;
        const line = getLine(content, m.index);
        addFinding('CRITICAL', 'CI/CD Security', `Hardcoded secret in ${rel}:${line}`,
          `${m[0].trim()}\nSecret committed to the pipeline file.`,
          `Move to GitLab CI/CD Variables (Settings > CI/CD > Variables) with "Protected" + "Masked" flags.`,
          { file: rel, line }, 'high');
        totalIssues++;
      }

      // Echo of secrets in script blocks
      const echoSecretRegex = /-\s+echo[^\n]*\$(?:CI_)?\w*(?:TOKEN|SECRET|PASSWORD|KEY)\w*/gi;
      while ((m = echoSecretRegex.exec(content)) !== null) {
        const line = getLine(content, m.index);
        addFinding('CRITICAL', 'CI/CD Security', `Secret echoed to log in ${rel}:${line}`,
          `${m[0].trim()}\nGitLab masks variables flagged "Masked" but echoing still risks leaks via redirects, files, or partial matches.`,
          `Never echo secrets. Use them inline in commands without echo, or write to a file the pipeline immediately consumes.`,
          { file: rel, line }, 'high');
        totalIssues++;
      }
    }
  }

  // ── CircleCI ──
  const circleCi = path.join(projectPath, '.circleci', 'config.yml');
  if (fs.existsSync(circleCi)) {
    spinner.text = 'Auditing .circleci/config.yml...';
    let content;
    try { content = await fs.promises.readFile(circleCi, 'utf-8'); } catch { content = null; }
    if (content) {
      const rel = '.circleci/config.yml';

      // Orbs referenced by mutable tag (volatile, dev:*, or no version)
      const orbRegex = /^[ \t]+([\w-]+):\s*([\w-]+\/[\w-]+)@([\w.\-]+)/gim;
      let m;
      while ((m = orbRegex.exec(content)) !== null) {
        const ref = m[3];
        if (/^volatile$/i.test(ref) || /^dev:/i.test(ref)) {
          const line = getLine(content, m.index);
          addFinding('MEDIUM', 'CI/CD Security', `Mutable orb reference ${m[2]}@${ref} in ${rel}:${line}`,
            `Orbs with @volatile or @dev:* can change without notice. A maintainer can push malicious updates.`,
            `Pin to a fixed semver: ${m[2]}@1.2.3`,
            { file: rel, line }, 'medium');
          totalIssues++;
        }
      }

      // Echoing secrets
      const echoSecretRegex = /echo[^\n]*\$(?:CIRCLE_)?\w*(?:TOKEN|SECRET|PASSWORD|KEY)\w*/gi;
      while ((m = echoSecretRegex.exec(content)) !== null) {
        const line = getLine(content, m.index);
        addFinding('CRITICAL', 'CI/CD Security', `Secret echoed to log in ${rel}:${line}`,
          `${m[0].trim()}\nLeaks the secret in the CircleCI build log.`,
          `Never echo secrets. Use the env directly in commands.`,
          { file: rel, line }, 'high');
        totalIssues++;
      }
    }
  }

  if (totalIssues === 0) {
    addFinding('INFO', 'CI/CD Security', `${files.length} workflow(s) scanned, no issues`, '', '');
  } else {
    addFinding('INFO', 'CI/CD Security', `${files.length} workflow(s) scanned, ${totalIssues} issue(s) found`, '', '');
  }
}
