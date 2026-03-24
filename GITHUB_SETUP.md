# GitHub Setup Guide for Blackbox Umbra

This guide walks through publishing Blackbox Umbra to a private or public GitHub repository with proper security controls.

---

## Step 1: Create the GitHub Repository

### On GitHub.com:

1. **Sign in** to your Blackbox Intelligence Group GitHub account
2. **Create a new repository**:
   - Name: `umbra` or `blackbox-umbra`
   - Description: "Automated Penetration Testing & Vulnerability Discovery Framework"
   - Visibility: **Choose one**:
     - **Private** (restrict to authorized team members only) — RECOMMENDED
     - **Public** (allow anyone to view, but not modify) — if you want public awareness
   - Initialize: **NOT** adding README/license (we have our own)
   - License: Select "None" (we'll use custom proprietary LICENSE file)

3. **Copy the repository URL** (HTTPS or SSH):
   - HTTPS: `https://github.com/blackboxintelgroup/umbra.git`
   - SSH: `git@github.com:blackboxintelgroup/umbra.git`

---

## Step 2: Initialize Git & Commit Local

```bash
cd ~/tools/bbr

# Initialize git (if not already done)
git init

# Configure git identity (optional but recommended)
git config user.name "Alexander Morrow"
git config user.email "amorrow@blackboxintelgroup.com"

# Add all files EXCEPT sensitive outputs
git add .
git status  # Verify only source files, not engagements/

# Create initial commit
git commit -m "Initial commit: Blackbox Umbra v1.0 - Automated pentest framework"
```

---

## Step 3: Connect to GitHub & Push

```bash
# Add remote
git remote add origin https://github.com/blackboxintelgroup/umbra.git

# OR if using SSH (requires GitHub SSH key setup):
git remote add origin git@github.com:blackboxintelgroup/umbra.git

# Verify remote
git remote -v

# Push to GitHub (creates main branch)
git branch -M main
git push -u origin main
```

---

## Step 4: Configure GitHub Repository Settings

### On GitHub.com Repository Settings:

#### Branches
1. **Go to**: Settings → Branches
2. **Set main branch protection**:
   - ✅ Require pull request reviews before merging
   - ✅ Require status checks to pass
   - ✅ Require branches to be up-to-date before merging
   - ✅ Require code reviews from code owners
   - ⚠️ **Restrict who can push to matching branches**: Only authorized team members

#### Visibility & Access
1. **Go to**: Settings → Collaborators and teams
2. **Add collaborators** (if private repo):
   - Alexander Morrow (Owner)
   - [Other Blackbox Intelligence Group LLC team members]
3. Set permissions:
   - Team leads: `Maintain` (can manage but not delete)
   - Operators: `Read` (view only)
   - Interns/contractors: `None` (if public, they see it; if private, no access)

#### Rules
1. **Go to**: Settings → Rules
2. **Create branch protection rule**:
   - Applies to: `main`
   - ✅ Require status checks to pass
   - ✅ Require approval from code owners
   - ✅ Dismiss stale pull request approvals
   - ✅ Restrict who can push to matching branches
   - ⚠️ **Allow force pushes**: NO
   - ⚠️ **Allow deletions**: NO

---

## Step 5: Lock Down Pull Requests

### Create a CODEOWNERS file

```bash
# In ~/tools/bbr/.github/CODEOWNERS
mkdir -p .github
cat > .github/CODEOWNERS << 'EOF'
# Blackbox Umbra — Code Owners
# All files require approval from owners

*                                @amorrow           # Alexander Morrow  
LICENSE                         @amorrow            # Proprietary license is immutable
CONTRIBUTING.md                 @amorrow            # No external contributions allowed
README.md                        @amorrow            # Project documentation
EOF

git add .github/CODEOWNERS
git commit -m "Add CODEOWNERS for strict review"
git push
```

### Enforce in Settings:
1. **Settings → Branches → Branch protection rules**
2. **Edit "main" rule**:
   - ✅ Require code owner review
   - ✅ Require status checks to pass before merging
   - ⚠️ Allow only `@amorrow` (or authorized users) to dismiss PR reviews

---

## Step 6: Create "Read-Only" Branch Policy

### Option A: Disable Pull Requests Entirely (Most Restrictive)

```bash
# Via GitHub CLI:
gh repo edit --enable-discussions false --enable-projects false

# Via Settings (UI):
# Settings → Features → Disable "Discussions" & "Projects"
```

### Option B: Auto-Reject All PRs via Actions (Recommended)

Create `.github/workflows/reject-external-prs.yml`:

```yaml
name: ⛔ Reject External Pull Requests

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  reject:
    runs-on: ubuntu-latest
    if: github.actor != 'amorrow'  # Replace with authorized GitHub usernames
    steps:
      - name: Close Unauthorized PR
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.pulls.update({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: context.issue.number,
              state: 'closed'
            });
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: '❌ This repository does not accept pull requests or external contributions.\n\nBlackbox Umbra is a proprietary tool. See LICENSE for restrictions.\n\nFor authorized team members: submit code changes through internal processes.'
            });
```

Then commit & push:
```bash
git add .github/workflows/reject-external-prs.yml
git commit -m "Add GitHub Actions: auto-reject unauthorized PRs"
git push
```

---

## Step 7: Set Repository Description & Topics

### On GitHub.com:

1. **Go to**: Repository root page
2. **Click edit** (pencil icon next to repo name)
3. **Add topics**:
   - `penetration-testing`
   - `security-tools`
   - `reconnaissance`
   - `vulnerability-scanning`
   - `automated-recon`
   - `proprietary`
   - `no-modifications`

4. **Add description**: 
   > "Automated Penetration Testing & Vulnerability Discovery Framework by Blackbox Intelligence Group LLC. **Proprietary — Read-Only. No External Contributions Accepted.**"

---

## Step 8: Setup GitHub Pages (Optional)

To host documentation at `https://github.com/blackboxintelgroup/umbra`:

```bash
# Nothing special needed — GitHub automatically renders README.md
# Your .md files appear in the repo view
```

---

## Step 9: Create Release Tags

```bash
# Tag the release
git tag -a v1.0 -m "Blackbox Umbra v1.0 - Initial Release"
git push origin v1.0

# Create release on GitHub (CLI or web UI):
gh release create v1.0 --title "Blackbox Umbra v1.0" --notes "Initial release"
```

---

## Step 10: Ongoing Maintenance

### For Internal Updates Only:

```bash
# Pull latest
git pull origin main

# Make changes (authorized users only)
git checkout -b internal/feature-name
git add .
git commit -m "Add feature: [description]"
git push origin internal/feature-name

# Create PR (internal review only)
# Get approval from @amorrow
# Merge to main via GitHub UI

# Never: Allow external PRs, forks from forks, or modifications
```

---

## Final Checklist

- ✅ Repository created (private or public)
- ✅ LICENSE file in place (proprietary terms)
- ✅ README.md describes the tool & authorization requirement
- ✅ CONTRIBUTING.md explicitly forbids contributions
- ✅ .gitignore prevents engagement outputs from committing
- ✅ requirements.txt lists Python dependencies
- ✅ CODEOWNERS file specifies authorized reviewers
- ✅ Branch protection rules enforce code review
- ✅ GitHub Actions auto-reject unauthorized PRs
- ✅ Topics & description set
- ✅ Release tags created
- ✅ Team members added with appropriate permissions

---

## GitHub URL

Once pushed:
```
https://github.com/blackboxintelgroup/umbra
```

Share this link with:
- ✅ Team members (if private repo)
- ✅ Authorized partners under NDA
- ❌ Random the internet (if you want to keep it truly proprietary)

---

**The shadow sees all.** 🕵️
