# Blackbox Umbra — GitHub Push Instructions

**Status**: ✅ Repository is locally committed and ready to push.

---

## Step-by-Step: Push to GitHub

### 1️⃣ Create Repository on GitHub.com

**Go to:** https://github.com/new

**Fill in these details:**

| Field | Value |
|-------|-------|
| **Repository name** | `Umbra` |
| **Description** | `Automated Penetration Testing & Vulnerability Discovery Framework` |
| **Visibility** | **Private** (restrict to team) OR **Public** (if you want visible, but locked) |
| **Initialize with README** | ❌ **(DO NOT)** — we have our own |
| **License** | None (we use custom proprietary license) |
| **Gitignore** | None (we have our own) |

**Click:** "Create Repository"

---

### 2️⃣ Push Local Repository to GitHub

After creating the repo, GitHub will show you setup instructions. **Use these commands:**

```bash
cd ~/tools/bbr

# Rename master to main (modern convention)
git branch -m master main

# Add remote (replace USERNAME with your GitHub username)
git remote add origin https://github.com/USERNAME/Umbra.git

# Push to GitHub
git push -u origin main

# Verify
git remote -v
```

**Output should show:**
```
origin  https://github.com/USERNAME/Umbra.git (fetch)
origin  https://github.com/USERNAME/Umbra.git (push)
```

---

### 3️⃣ Quick Verification

After pushing, verify on GitHub:

```bash
# Check what's on GitHub now
git log origin/main --oneline

# Verify files are there
git ls-remote origin
```

---

## 🔐 Lock Down the Repository (After Push)

### Via GitHub Web UI:

1. **Go to:** Settings → Branches
2. **Under "Branch protection rules"**, click **"Add rule"**

   | Setting | Value |
   |---------|-------|
   | Branch name pattern | `main` |
   | ✅ Require a pull request before merging | YES |
   | ✅ Require status checks to pass | YES |
   | ✅ Require code reviews from code owners | YES |
   | ✅ Restrict who can push | Only authorized members |
   | ✅ Require branches to be up to date | YES |
   | ❌ Allow force pushes | NO |
   | ❌ Allow deletions | NO |

3. **Click:** "Save changes"

### Add Collaborators (Settings → Collaborators):

Only add **authorized Blackbox Intelligence Group LLC** team members.

---

## ✅ What Gets Pushed

```
✅ Source Code (Python modules)
✅ Documentation (README, guides, brand guide)
✅ License (proprietary)
✅ Configuration (.gitignore, requirements.txt)

❌ NOT Pushed:
❌ engagements/ (local engagement data)
❌ wordlists/ (large external resources)
❌ __pycache__/ (compiled Python)
❌ .vscode/ (local IDE settings)
```

---

## 🚀 Done!

Your GitHub URL will be:
```
https://github.com/USERNAME/Umbra
```

Share this **only with authorized team members**.

---

## Troubleshooting Push

### "fatal: not a git repository"
```bash
cd ~/tools/bbr  # Make sure you're in the right directory
```

### "Permission denied (publickey)"
You need to set up GitHub SSH keys:
```bash
ssh-keygen -t ed25519 -C "amorrow@blackboxintelgroup.com"
# Or use HTTPS instead of SSH (no key setup needed)
```

### "remote origin already exists"
```bash
git remote set-url origin https://github.com/USERNAME/Umbra.git
git push -u origin main
```

### "rejected... because the remote contains work"
```bash
git pull origin main --allow-unrelated-histories
git push origin main
```

---

**Ready to push? Run the commands in Step 2!** 🚀

*The shadow sees all.* 🕵️
